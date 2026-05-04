package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

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

// pushBlockRule sends a DROP rule to Secure Framework via REST API.
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

func healthHandler(w http.ResponseWriter, r *http.Request) { proxyGet(w, idsURL+"/health") }

func alertsHandler(w http.ResponseWriter, r *http.Request) {
	url := idsURL + "/alerts"
	if last := r.URL.Query().Get("last"); last != "" {
		url += "?last=" + last
	}
	proxyGet(w, url)
}

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

// rulesHandler handles GET (proxy+filter) and POST (force source=agent) for /rules
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

// --- SSE bridge từ Suricata → hub ---

func runBridge() {
	sseFails := 0
	for {
		if err := consumeSSE(); err != nil {
			sseFails++
			log.Printf("SSE [%d]: %v — retry 3s", sseFails, err)
			if sseFails >= 5 {
				log.Println("Switching to polling mode")
				runPoller()
				return
			}
		} else {
			sseFails = 0
		}
		time.Sleep(3 * time.Second)
	}
}

func consumeSSE() error {
	resp, err := (&http.Client{}).Get(idsURL + "/stream")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	log.Printf("SSE upstream connected: %s/stream", idsURL)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
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

func runPoller() {
	log.Println("Polling mode — 2s interval")
	var lastCount int
	client := &http.Client{Timeout: 5 * time.Second}
	for range time.NewTicker(2 * time.Second).C {
		resp, err := client.Get(fmt.Sprintf("%s/alerts?last=100", idsURL))
		if err != nil {
			continue
		}
		var data map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&data)
		resp.Body.Close()
		count := int(data["count"].(float64))
		alerts, _ := data["alerts"].([]interface{})
		if count > lastCount && lastCount > 0 {
			newN := count - lastCount
			if newN > len(alerts) {
				newN = len(alerts)
			}
			for _, a := range alerts[len(alerts)-newN:] {
				msg, _ := json.Marshal(a)
				hub.broadcast(msg)
			}
		}
		lastCount = count
	}
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

// runServiceHeartbeat polls IDS API /service-health every 30s (passive flow inference
// from Suricata eve.json — no active TCP probe needed, IDS is inside GNS3 and sees all traffic).
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

func main() {
	log.Printf("IDS Agent — IDS: %s  SF: %s  listen: %s", idsURL, sfURL, listenAddr)
	go runBridge()
	go runServiceHeartbeat()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/alerts", alertsHandler)
	mux.HandleFunc("/flows", flowsHandler)
	mux.HandleFunc("/ws", wsHandler)
	mux.HandleFunc("/events", eventsHandler)
	mux.HandleFunc("/rules", rulesHandler)
	mux.HandleFunc("/rules/", rulesDeleteHandler)
	mux.HandleFunc("/autoblock", autoblockHandler)
	mux.HandleFunc("/autoblock/unblock/", unblockHandler)

	log.Fatal(http.ListenAndServe(listenAddr, cors(mux)))
}
