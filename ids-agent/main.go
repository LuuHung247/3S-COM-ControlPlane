// Package main — ids-agent: cầu nối (Go HTTP bridge) giữa
//   • IDS API (Suricata tail server, ngoài NAT trên IDS VM)
//   • Secure Framework (REST API quản lý LEAF rule)
//   • Client (FE Next.js, intelligence-layer agent, harness eval)
//
// Trách nhiệm chính:
//   1. Tiêu thụ SSE stream từ IDS API → broadcast lại cho mọi WS/SSE client local.
//   2. Proxy các GET /alerts /flows /health từ IDS API (clients không phải đi qua NAT).
//   3. Stamp source=agent và forward POST/DELETE /rules sang Secure Framework
//      (lá chắn provenance — chỉ rule đi qua đây mới được SF coi là "do agent đẩy").
//   4. Polling /service-health 30s/lần → broadcast trạng thái service.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// ── Cấu hình URL backend (có thể override qua biến môi trường) ────────────
//   idsURL  : IDS API (Suricata tail server) — TẤT CẢ alert/flow gốc đến từ đây
//   sfURL   : Secure Framework — đích đẩy rule (đi tiếp qua gNMI tới LEAF)
//   listen  : cổng HTTP của chính ids-agent này (FE và intel agent gọi vào)
var (
	idsURL     = envOr("IDS_API_URL", "http://10.10.6.238:8765")
	sfURL      = envOr("SF_API_URL", "http://10.10.6.238:9090")
	listenAddr = envOr("AGENT_ADDR", ":8766")
)

// ── Heartbeat snapshot cache ───────────────────────────────────────────────
// Stores latest heartbeat JSON per service name so new SSE clients receive
// current service status immediately on connect (no 30s wait).

var (
	hbMu    sync.RWMutex
	hbCache = make(map[string][]byte)
)

func cacheHeartbeat(name string, msg []byte) {
	hbMu.Lock()
	cp := make([]byte, len(msg))
	copy(cp, msg)
	hbCache[name] = cp
	hbMu.Unlock()
}

func heartbeatSnapshot() [][]byte {
	hbMu.RLock()
	defer hbMu.RUnlock()
	out := make([][]byte, 0, len(hbCache))
	for _, v := range hbCache {
		out = append(out, v)
	}
	return out
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// --- Hub: broadcast tới cả WebSocket lẫn SSE clients ---

type Hub struct {
	mu         sync.RWMutex
	wsClients  map[*websocket.Conn]struct{}
	sseClients map[chan []byte]struct{}
}

var hub = &Hub{
	wsClients:  make(map[*websocket.Conn]struct{}),
	sseClients: make(map[chan []byte]struct{}),
}

func (h *Hub) broadcast(msg []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.wsClients {
		_ = c.WriteMessage(websocket.TextMessage, msg)
	}
	for ch := range h.sseClients {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (h *Hub) addWS(c *websocket.Conn)      { h.mu.Lock(); h.wsClients[c] = struct{}{}; h.mu.Unlock() }
func (h *Hub) removeWS(c *websocket.Conn)   { h.mu.Lock(); delete(h.wsClients, c); h.mu.Unlock() }
func (h *Hub) addSSE(ch chan []byte)         { h.mu.Lock(); h.sseClients[ch] = struct{}{}; h.mu.Unlock() }
func (h *Hub) removeSSE(ch chan []byte)      { h.mu.Lock(); delete(h.sseClients, ch); h.mu.Unlock() }

// pushBlockRule — đẩy 1 rule DROP sang Secure Framework qua REST.
// Dùng cho path "autoblock thủ công" (POST /autoblock {src_ip}).
// Path "agent tự ra quyết định" đi qua POST /rules (rulesPostHandler bên dưới).
//
// rule_id: nếu rỗng thì auto-sinh "agent-<ip-có-dấu-gạch>" — đảm bảo idempotent
// (cùng IP gọi lại sẽ override cùng rule, không tạo trùng).
//
// source=agent: đóng dấu provenance — SF dựa vào field này để phân biệt rule do
// AGENT đẩy (TTL ngắn, dynamic) vs do OPERATOR/SDNC đẩy (baseline policy).
func pushBlockRule(srcIP, ruleID, reason string) ([]byte, error) {
	if ruleID == "" {
		safe := strings.NewReplacer(".", "-", "/", "-").Replace(srcIP)
		ruleID = "agent-" + safe
	}
	cidr := srcIP
	if !strings.Contains(cidr, "/") {
		cidr += "/32"
	}
	payload := map[string]interface{}{
		"rule_id":  ruleID,
		"action":   "DROP",
		"src_ip":   cidr,
		"priority": 50,
		"source":   "agent",
		"comment":  reason,
	}
	body, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(sfURL+"/api/rules", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	result, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("SF %d: %s", resp.StatusCode, string(result))
	}
	return result, nil
}

// --- HTTP Handlers ---

var upgrader = websocket.Upgrader{
	CheckOrigin: func(*http.Request) bool { return true },
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	hub.addWS(conn)
	defer func() { hub.removeWS(conn); conn.Close() }()
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}

func eventsHandler(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan []byte, 64)
	hub.addSSE(ch)
	defer hub.removeSSE(ch)

	fmt.Fprintf(w, "data: {\"type\":\"connected\"}\n\n")
	flusher.Flush()

	// Replay latest heartbeat per service so new clients see status immediately
	for _, msg := range heartbeatSnapshot() {
		fmt.Fprintf(w, "data: %s\n\n", msg)
	}
	flusher.Flush()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case msg := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// proxyGet — generic helper: GET url upstream, đổ nguyên response về client.
// Nếu upstream chết → 503 + body {"status":"offline"} (FE dùng để hiện "offline").
func proxyGet(w http.ResponseWriter, targetURL string) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(targetURL)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(503)
		json.NewEncoder(w).Encode(map[string]string{"status": "offline"})
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	io.Copy(w, resp.Body)
}

// ── 3 proxy handler — "LẤY DATA TỪ IDS API" theo yêu cầu của client ──
// FE/harness gọi vào ids-agent (local) → ids-agent đi tiếp sang IDS VM qua NAT.
// Tách lớp như vậy để: (a) client không phải biết URL IDS thật ngoài NAT,
// (b) thêm CORS + cache-control + xử lý timeout/offline đồng nhất.

// GET /health → IDS API /health (kiểm tra Suricata còn tail eve.json không)
func healthHandler(w http.ResponseWriter, r *http.Request) { proxyGet(w, idsURL+"/health") }

// GET /alerts[?last=N] → IDS API /alerts — kéo alert buffer trong RAM của ids-api.py
// (ids-api.py tail /var/log/suricata/eve.json và giữ ring buffer alert mới nhất).
func alertsHandler(w http.ResponseWriter, r *http.Request) {
	url := idsURL + "/alerts"
	if last := r.URL.Query().Get("last"); last != "" {
		url += "?last=" + last
	}
	proxyGet(w, url)
}

// GET /flows[?last=N&since=ISO] → IDS API /flows — buffer flow event của Suricata.
func flowsHandler(w http.ResponseWriter, r *http.Request) {
	url := idsURL + "/flows"
	q := r.URL.Query()
	params := []string{}
	if last := q.Get("last"); last != "" {
		params = append(params, "last="+last)
	}
	if since := q.Get("since"); since != "" {
		params = append(params, "since="+since)
	}
	if len(params) > 0 {
		url += "?" + strings.Join(params, "&")
	}
	proxyGet(w, url)
}

// ── /rules handler: 2 chiều — đọc rule trên LEAF + đẩy rule mới sang SF ──
// GET  /rules[?source=agent] : lấy rule hiện có trên các LEAF (qua SF gNMI),
//                              có thể lọc theo source.
// POST /rules                 : ÉP source=agent rồi forward sang SF /api/rules
//                              → SF làm gNMI Set xuống LEAF.
//   ⇒ Đây là cơ chế "đóng dấu provenance" lá chắn quan trọng:
//     intel-agent enforce gọi vào ĐÂY (không gọi thẳng SF), nên SF có thể tin
//     rằng mọi POST từ ids-agent là rule do agent quyết định.
func rulesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		rulesGetHandler(w, r)
	case http.MethodPost:
		rulesPostHandler(w, r)
	default:
		http.Error(w, "GET or POST only", 405)
	}
}

// rulesGetHandler proxies GET /rules → SF /api/rules with optional ?source= filter
func rulesGetHandler(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(sfURL + "/api/rules")
	if err != nil {
		w.WriteHeader(503)
		json.NewEncoder(w).Encode(map[string]string{"error": "SF offline"})
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Cache-Control", "no-store")

	sourceFilter := r.URL.Query().Get("source")
	if sourceFilter == "" {
		io.Copy(w, resp.Body)
		return
	}
	var rules []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&rules); err != nil {
		// Not a JSON array — return as-is
		io.Copy(w, resp.Body)
		return
	}
	filtered := make([]map[string]interface{}, 0)
	for _, rule := range rules {
		if src, _ := rule["source"].(string); src == sourceFilter {
			filtered = append(filtered, rule)
		}
	}
	json.NewEncoder(w).Encode(filtered)
}

// rulesPostHandler accepts a full rule body, forces source=agent, and forwards to SF
func rulesPostHandler(w http.ResponseWriter, r *http.Request) {
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}
	body["source"] = "agent" // force provenance server-side
	raw, _ := json.Marshal(body)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(sfURL+"/api/rules", "application/json", bytes.NewReader(raw))
	if err != nil {
		w.WriteHeader(503)
		json.NewEncoder(w).Encode(map[string]string{"error": "SF offline"})
		return
	}
	defer resp.Body.Close()
	result, _ := io.ReadAll(resp.Body)
	w.WriteHeader(resp.StatusCode)
	w.Write(result)
}

// rulesDeleteHandler handles DELETE /rules/{rule_id} — forward to SF
func rulesDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "DELETE only", 405)
		return
	}
	parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
	ruleID := parts[len(parts)-1]
	if ruleID == "" || ruleID == "rules" {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "rule_id required"})
		return
	}
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest(http.MethodDelete, sfURL+"/api/rules/"+ruleID, nil)
	resp, err := client.Do(req)
	if err != nil {
		w.WriteHeader(503)
		json.NewEncoder(w).Encode(map[string]string{"error": "SF offline"})
		return
	}
	defer resp.Body.Close()
	result, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(result)
}

// autoblockHandler handles GET (status) and POST (manual block).
func autoblockHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sf_url": sfURL,
		})
		return
	}

	if r.Method == http.MethodPost {
		// Manual block: POST /autoblock {src_ip, rule_id?, reason?}
		var req struct {
			SrcIP  string `json:"src_ip"`
			RuleID string `json:"rule_id"`
			Reason string `json:"reason"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.SrcIP == "" {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": "src_ip required"})
			return
		}
		if req.Reason == "" {
			req.Reason = "manual block via IDS Agent"
		}
		result, err := pushBlockRule(req.SrcIP, req.RuleID, req.Reason)
		if err != nil {
			w.WriteHeader(500)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Write(result)
		return
	}

	http.Error(w, "GET or POST only", 405)
}

// unblockHandler: DELETE /autoblock/unblock/{rule_id}
func unblockHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		http.Error(w, "DELETE or POST only", 405)
		return
	}
	parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
	ruleID := parts[len(parts)-1]
	if ruleID == "" || ruleID == "unblock" {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "rule_id required"})
		return
	}
	hclient := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest(http.MethodDelete, sfURL+"/api/rules/"+ruleID, nil)
	resp, err := hclient.Do(req)
	if err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	result, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(result)
}

// ════════════════════════════════════════════════════════════════════════════
//  ★ CHỖ "LẤY IDS" QUAN TRỌNG NHẤT — SSE bridge từ Suricata → hub ★
// ════════════════════════════════════════════════════════════════════════════
//
// Đây là đường dẫn LIVE chính lấy alert/flow từ Suricata:
//   ids-vm/ids-api.py tail eve.json → expose SSE ở idsURL+"/stream"
//                                  ↓ (consumeSSE giữ kết nối SSE bền)
//                                ids-agent
//                                  ↓ hub.broadcast()
//                  tất cả WS/SSE client local (FE, intel-agent, harness)
//
// Tại sao SSE thay vì poll:
//   - Poll bị miss event khi Suricata restart (ring buffer reset → "đã xem N
//     lần" ở client sai), và che giấu bug stale upstream.
//
// 2 watchdog:
//   1. Stall-timeout (30s): KHÔNG nhận được dòng nào từ upstream (kể cả `:hb`)
//      → cancel context, kết nối lại (Suricata mỗi 15s gửi `: hb`, miss 2 → reconnect).
//   2. Max connection-age (4 phút): force reconnect định kỳ. Phát hiện case
//      hb còn nhưng broadcast list ở ids-api.py đã reset (heartbeat đến đều
//      nhưng alert thật không bao giờ tới) — watchdog stall không bắt được.
//
// Backoff lũy thừa khi reconnect, trần 30s.

const (
	sseStallTimeout     = 30 * time.Second
	sseMaxBackoff       = 30 * time.Second
	sseInitialBackoff   = time.Second
	// Force re-Dial periodically — defends against the case where Suricata's
	// `: hb` keeps coming but the broadcast list on upstream IDS API was
	// silently reset (TCP connection alive but no alerts delivered). Caught
	// in production: ids-api `sse_clients=0` while local side believed
	// connection healthy. Watchdog alone (30s stall) cannot detect this
	// because heartbeats reset the timer.
	sseMaxConnectionAge = 4 * time.Minute
)

// runBridge — vòng đời ngoài: gọi consumeSSE liên tục, backoff khi lỗi.
// Chạy như goroutine từ main() — không bao giờ dừng (trừ khi process exit).
func runBridge() {
	backoff := sseInitialBackoff
	for {
		err := consumeSSE()
		if err != nil {
			log.Printf("SSE: %v — retry in %s", err, backoff)
		} else {
			log.Println("SSE upstream closed cleanly — reconnecting")
			backoff = sseInitialBackoff
		}
		time.Sleep(backoff)
		if backoff < sseMaxBackoff {
			backoff *= 2
			if backoff > sseMaxBackoff {
				backoff = sseMaxBackoff
			}
		}
	}
}

// consumeSSE — 1 phiên đọc SSE từ IDS API.
//   GET idsURL+"/stream"  → mỗi event tail từ eve.json → `data: <json>\n\n`
// Đọc line-by-line bằng bufio.Scanner, mỗi line có prefix "data: " → broadcast
// cho hub (tất cả WS/SSE client đăng ký nhận sẽ thấy event ngay).
func consumeSSE() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Mở kết nối tới IDS API endpoint streaming
	req, err := http.NewRequestWithContext(ctx, "GET", idsURL+"/stream", nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{}).Do(req) // không đặt Timeout — đây là stream dài hạn
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	log.Printf("SSE upstream connected: %s/stream", idsURL)

	// Watchdog: if no line received in sseStallTimeout, cancel the request.
	// Cancelling closes resp.Body which makes scanner.Scan() return false.
	var lastSignalNs atomic.Int64
	lastSignalNs.Store(time.Now().UnixNano())

	connectedAt := time.Now()
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				// Watchdog 1: stall (no upstream signal for sseStallTimeout)
				if time.Since(time.Unix(0, lastSignalNs.Load())) > sseStallTimeout {
					log.Printf("SSE upstream silent > %s — forcing reconnect", sseStallTimeout)
					cancel()
					return
				}
				// Watchdog 2: max connection age — guards against silent upstream
				// broadcast-list reset where heartbeats keep flowing but alerts don't.
				if time.Since(connectedAt) > sseMaxConnectionAge {
					log.Printf("SSE upstream connection age > %s — forcing reconnect", sseMaxConnectionAge)
					cancel()
					return
				}
			}
		}
	}()

	scanner := bufio.NewScanner(resp.Body)
	// Larger buffer for occasional big alert events (default 64K is fine for
	// most, but bump to 256K to be safe).
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)
	for scanner.Scan() {
		line := scanner.Text()
		// ANY line received resets the stall timer — including SSE comment
		// heartbeats `: hb` which carry no data but prove the upstream is alive.
		lastSignalNs.Store(time.Now().UnixNano())

		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data: "))
		if data == "" || data == "heartbeat" {
			continue
		}
		hub.broadcast([]byte(data))
	}
	return scanner.Err()
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// runServiceHeartbeat — polling /service-health của IDS API mỗi 30s.
// Đây là chỗ thứ 5 (ngoài SSE + 3 proxy GET) lấy data từ IDS:
//   - Không probe TCP chủ động (Suricata đã thấy mọi packet trong GNS3 fabric,
//     suy ngược trạng thái service từ flow event là đủ — "passive inference").
//   - Mỗi service status được cache vào hbCache + broadcast realtime cho hub,
//     để FE mới connect cũng thấy trạng thái ngay (không phải đợi 30s).
func runServiceHeartbeat() {
	client := &http.Client{Timeout: 5 * time.Second}
	emit := func() {
		resp, err := client.Get(idsURL + "/service-health")
		if err != nil {
			return
		}
		defer resp.Body.Close()

		var result struct {
			Services []struct {
				Name   string `json:"name"`
				IP     string `json:"ip"`
				Port   int    `json:"port"`
				Zone   string `json:"zone"`
				Status string `json:"status"`
			} `json:"services"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return
		}

		ts := time.Now().UTC().Format(time.RFC3339)
		for _, svc := range result.Services {
			msg, _ := json.Marshal(map[string]interface{}{
				"type":      "heartbeat",
				"service":   svc.Name,
				"zone":      svc.Zone,
				"status":    svc.Status,
				"dest_ip":   fmt.Sprintf("%s:%d", svc.IP, svc.Port),
				"timestamp": ts,
				"method":    "flow-inference",
			})
			cacheHeartbeat(svc.Name, msg)
			hub.broadcast(msg)
		}
	}

	emit()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		emit()
	}
}

// main — entry point. Khởi 2 goroutine nền + đăng ký HTTP handler.
//
// Tóm tắt mọi chỗ "lấy data từ IDS API" trong file này:
//   1. consumeSSE         → idsURL+"/stream"         (live stream alert/flow)
//   2. healthHandler      → idsURL+"/health"          (kiểm tra Suricata sống)
//   3. alertsHandler      → idsURL+"/alerts"          (đọc buffer alert)
//   4. flowsHandler       → idsURL+"/flows"           (đọc buffer flow)
//   5. runServiceHeartbeat→ idsURL+"/service-health"  (polling 30s/lần)
//
// Mọi chỗ "đẩy data sang SF" (đi tiếp tới LEAF qua gNMI):
//   - pushBlockRule + rulesPostHandler + rulesDeleteHandler + unblockHandler
//     → sfURL+"/api/rules[/...]"  (đều ép source=agent server-side)
func main() {
	log.Printf("IDS Agent — IDS: %s  SF: %s  listen: %s", idsURL, sfURL, listenAddr)
	go runBridge()            // goroutine: giữ SSE từ IDS API → broadcast tới hub
	go runServiceHeartbeat()  // goroutine: polling service-health 30s → broadcast

	// HTTP routes mà client (FE, intel-agent, harness) gọi vào
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)        // proxy IDS health
	mux.HandleFunc("/alerts", alertsHandler)        // proxy alert buffer (lấy IDS)
	mux.HandleFunc("/flows", flowsHandler)          // proxy flow buffer (lấy IDS)
	mux.HandleFunc("/ws", wsHandler)                // WebSocket subscriber
	mux.HandleFunc("/events", eventsHandler)        // SSE subscriber (FE dùng)
	mux.HandleFunc("/rules", rulesHandler)          // GET list / POST đẩy rule (sang SF)
	mux.HandleFunc("/rules/", rulesDeleteHandler)   // DELETE rule (sang SF)
	mux.HandleFunc("/autoblock", autoblockHandler)  // manual block thủ công
	mux.HandleFunc("/autoblock/unblock/", unblockHandler)

	log.Fatal(http.ListenAndServe(listenAddr, cors(mux)))
}
