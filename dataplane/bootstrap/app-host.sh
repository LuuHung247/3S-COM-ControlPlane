#!/bin/sh
# Bootstrap Alpine-3 (APP zone, 10.2.100.10)
# Role: application tier — only legitimate traffic, no attack mode
#   - python :8080 API server (handles /api/order, /api/data)
#   - baseline-noise cron: APP→DB query every 60s (ALLOW per policy)
#   - health-poll cron: APP→WEB health check every 60s (tests DENY — caught by LEAF iptables, not Suricata)
# Paste into: telnet 112.137.129.232:5014  (login: root, no password)
set -e

echo "[app] installing packages"
apk add --no-cache python3 curl busybox-extras 2>&1 | tail -3

# --- python app server ---
cat > /usr/local/bin/app-server.py <<'PY'
#!/usr/bin/env python3
"""APP tier API — connects to DB for orders and data queries."""
import socket, time
from http.server import HTTPServer, BaseHTTPRequestHandler

DB_HOST, DB_PORT = "10.1.200.10", 5432

def query_db(sql):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((DB_HOST, DB_PORT))
        s.sendall((sql + "\n").encode())
        data = s.recv(256).decode(errors="replace").strip()
        s.close()
        return data
    except Exception as e:
        return f"db_err:{e}"

class Handler(BaseHTTPRequestHandler):
    def reply(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())
    def do_GET(self):
        if self.path == "/health":
            return self.reply(200, "app-ok")
        if self.path.startswith("/api/data"):
            return self.reply(200, f"data: {query_db('SELECT * FROM products')}")
        if self.path.startswith("/api/order"):
            return self.reply(200, f"order: {query_db('INSERT INTO orders VALUES(...)')}")
        return self.reply(404, "not found")
    def log_message(self, *a, **k): pass

HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
PY
chmod +x /usr/local/bin/app-server.py

cat > /etc/init.d/app-server <<'OPENRC'
#!/sbin/openrc-run
name="app-server"
command="/usr/local/bin/app-server.py"
command_background=true
pidfile="/run/app-server.pid"
output_log="/var/log/app-server.log"
error_log="/var/log/app-server.log"
depend() { need net; }
OPENRC
chmod +x /etc/init.d/app-server

# --- baseline noise (legitimate traffic) ---
cat > /usr/local/bin/baseline-noise.sh <<'NOISE'
#!/bin/sh
# APP→DB (ALLOW per policy) — normal application flow
echo "SELECT count(*) FROM sessions" | nc -w 2 10.1.200.10 5432 >> /var/log/noise.log 2>&1
# APP→WEB (DENY per policy — LEAF drops silently, no Suricata alert for this)
curl -sf --max-time 2 http://10.1.100.10/health >> /var/log/noise.log 2>&1
NOISE
chmod +x /usr/local/bin/baseline-noise.sh

cat > /etc/crontabs/root <<'CRON'
* * * * * /usr/local/bin/baseline-noise.sh
CRON

rc-update add app-server default 2>&1 | tail -1
service app-server restart
rc-update add crond default 2>&1 | tail -1
service crond restart

sleep 2
curl -sf http://localhost:8080/health && echo "← app :8080 OK" || echo "← app FAIL"
curl -sf http://localhost:8080/api/data | head -c 60 && echo
echo "[app] DONE — APP server :8080 + baseline noise cron active"
