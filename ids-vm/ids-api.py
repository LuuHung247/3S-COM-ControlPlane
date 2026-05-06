#!/usr/bin/env python3
from http.server import ThreadingHTTPServer as HTTPServer, BaseHTTPRequestHandler
import json, os, time, threading, queue, datetime, collections

EVE = "/var/log/suricata/eve.json"
PORT = 8765
RING_ALERTS = 2000
RING_FLOWS = 2000
SSE_MAX_CLIENTS = 8
SSE_QUEUE_SIZE = 256
TAIL_POLL_SEC = 0.5

_alerts = collections.deque(maxlen=RING_ALERTS)
_flows = collections.deque(maxlen=RING_FLOWS)
_lock = threading.Lock()
_sse_clients = []
_sse_lock = threading.Lock()
_started_ts = time.time()

def _ts_to_epoch(ts_str):
    if not ts_str: return 0
    try:
        s = ts_str[:19].replace("T", " ")
        return datetime.datetime.strptime(s, "%Y-%m-%d %H:%M:%S").timestamp()
    except: return 0

def _broadcast(ev):
    msg = ("data: " + json.dumps(ev) + "\n\n").encode()
    with _sse_lock:
        dead = []
        for c in _sse_clients:
            try:
                c["q"].put_nowait(msg)
            except queue.Full:
                dead.append(c)
        for d in dead:
            try: _sse_clients.remove(d)
            except ValueError: pass

def tail_loop():
    inode = None
    pos = 0
    f = None
    while True:
        try:
            st = os.stat(EVE)
        except FileNotFoundError:
            time.sleep(2); continue
        if st.st_ino != inode or (f is None) or st.st_size < pos:
            if f:
                try: f.close()
                except: pass
            try:
                f = open(EVE, "r")
            except Exception:
                time.sleep(1); continue
            inode = st.st_ino
            pos = 0
        try:
            f.seek(pos)
            while True:
                line = f.readline()
                if not line: break
                pos += len(line)
                line = line.strip()
                if not line: continue
                try:
                    ev = json.loads(line)
                except: continue
                et = ev.get("event_type")
                if et == "alert":
                    with _lock: _alerts.append(ev)
                    _broadcast(ev)
                elif et == "flow":
                    with _lock: _flows.append(ev)
        except Exception:
            time.sleep(1); continue
        time.sleep(TAIL_POLL_SEC)

def get_alerts(last=None, since=None):
    with _lock:
        data = list(_alerts)
    if since:
        data = [a for a in data if a.get("timestamp", "") > since]
    if last:
        data = data[-last:]
    return data

def get_flows(last=100, since=None):
    last = min(int(last), 500)
    with _lock:
        data = list(_flows)
    if since:
        data = [a for a in data if a.get("timestamp", "") > since]
    return data[-last:]

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
    def _safe_write(self, b):
        try:
            self.wfile.write(b)
            return True
        except (BrokenPipeError, ConnectionResetError, OSError):
            return False
    def _safe_flush(self):
        try:
            self.wfile.flush()
            return True
        except (BrokenPipeError, ConnectionResetError, OSError):
            return False
    def do_OPTIONS(self):
        self.send_response(200); self.cors(); self.end_headers()
    def do_GET(self):
        try:
            self._route()
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception:
            try:
                self.send_response(500); self.cors(); self.end_headers()
            except: pass
            return
    def _route(self):
        path = self.path.split("?")[0]
        qs = dict(p.split("=") for p in self.path[len(path)+1:].split("&") if "=" in p)
        if path == "/stream":
            return self._stream()
        if path == "/health":
            suri = any(os.path.exists(p) for p in ("/var/run/suricata.pid", "/run/suricata.pid", "/run/suricata-zt.pid"))
            with _lock:
                ar = len(_alerts); fr = len(_flows)
            with _sse_lock:
                sc = len(_sse_clients)
            data = {
                "status":"ok","suricata":suri,
                "ts":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
                "ring_alerts":ar,"ring_flows":fr,"sse_clients":sc,
                "uptime_sec":int(time.time()-_started_ts),
            }
        elif path == "/alerts":
            try: last = int(qs.get("last", 0)) or None
            except: last = None
            since = qs.get("since","") or None
            alerts = get_alerts(last=last, since=since)
            sids = {}
            for a in alerts:
                sid = str(a.get("alert",{}).get("signature_id",""))
                sids[sid] = sids.get(sid,0)+1
            data = {"count":len(alerts),"summary":sids,"alerts":alerts}
        elif path == "/alerts/clear":
            data = {"cleared_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        elif path == "/flows":
            try: last_n = int(qs.get("last", 100))
            except: last_n = 100
            data = get_flows(last=last_n, since=qs.get("since", None))
        elif path == "/service-health":
            now = time.time()
            cutoff = now - 180
            seen = {}
            with _lock:
                flows = list(_flows)
            for ev in flows:
                ts_str = ev.get("flow",{}).get("end","") or ev.get("timestamp","")
                ts_e = _ts_to_epoch(ts_str)
                if ts_e and ts_e < cutoff: continue
                dp = ev.get("dest_port", 0)
                dst = ev.get("dest_ip", "")
                src = ev.get("src_ip", "")
                for key, ip, port in [
                    ("nginx:80","10.1.100.10",80),
                    ("db-mock:5432","10.1.200.10",5432),
                    ("python:8080","10.2.100.10",8080),
                    ("sshd:22","10.2.50.10",22),
                ]:
                    if (dst == ip and dp == port) or src == ip:
                        seen[key] = True
            services = [
                {"name":"nginx:80","ip":"10.1.100.10","port":80,"zone":"WEB"},
                {"name":"db-mock:5432","ip":"10.1.200.10","port":5432,"zone":"DB"},
                {"name":"python:8080","ip":"10.2.100.10","port":8080,"zone":"APP"},
                {"name":"sshd:22","ip":"10.2.50.10","port":22,"zone":"MGT"},
            ]
            data = {
                "services":[{**s, "status": "up" if seen.get(s["name"]) else "unknown"} for s in services],
                "ts":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
                "method":"flow-inference-ring",
            }
        else:
            data = {"error":"not found","endpoints":["/health","/alerts","/alerts/clear","/flows","/stream","/service-health"]}
        body = json.dumps(data,default=str).encode()
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",len(body))
        self.cors(); self.end_headers()
        self._safe_write(body)
    def _stream(self):
        with _sse_lock:
            if len(_sse_clients) >= SSE_MAX_CLIENTS:
                self.send_response(503); self.cors(); self.end_headers()
                self._safe_write(b'{"error":"too many SSE clients"}')
                return
            q = queue.Queue(maxsize=SSE_QUEUE_SIZE)
            client = {"q": q}
            _sse_clients.append(client)
        try:
            self.send_response(200)
            self.send_header("Content-Type","text/event-stream")
            self.send_header("Cache-Control","no-cache")
            self.send_header("Connection","keep-alive")
            self.cors(); self.end_headers()
            if not self._safe_write(b": connected\n\n"): return
            if not self._safe_flush(): return
            while True:
                try:
                    msg = q.get(timeout=15)
                except queue.Empty:
                    msg = b": hb\n\n"
                if not self._safe_write(msg): return
                if not self._safe_flush(): return
        finally:
            with _sse_lock:
                try: _sse_clients.remove(client)
                except ValueError: pass

def main():
    threading.Thread(target=tail_loop, daemon=True).start()
    HTTPServer(("0.0.0.0",PORT),H).serve_forever()

if __name__ == "__main__":
    main()
