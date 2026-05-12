#!/bin/sh
# Bootstrap Alpine-3 (APP zone, 10.2.100.10)
# Role: application tier
#   Normal:
#     - python :8080 API server (handles /api/order, /api/data)
#     - baseline-noise cron: APP→DB query every 60s (ALLOW per policy)
#     - health-poll cron: APP→WEB health check every 60s (tests DENY — LEAF drops)
#   Compromised (multi-mode via flag files):
#     /tmp/compromised-burst → 100 quick APP→DB queries/min (SID 9000031)
#     /tmp/compromised-bulk  → bulk SELECT triggering DB reply >4KB (SID 9000032)
#     /tmp/compromised-sql   → DROP TABLE / TRUNCATE patterns (SID 9000033)
#     /tmp/compromised-ssh   → cross-tier SSH attempts to WEB/DB (SID 9000035)
# Paste into: telnet 112.137.129.232:5014  (login: root, no password)
set -e

echo "[app] installing packages"
apk add --no-cache python3 curl busybox-extras 2>&1 | tail -3

# --- cleanup legacy artifacts from old app-host.sh ---
service crond stop 2>&1 | tail -1 || true
pkill -9 -f 'app-server' 2>/dev/null || true
pkill -9 -f 'attacker-app' 2>/dev/null || true
killall -9 python3 2>/dev/null || true
sleep 1

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
# Note: no `need net` — networking is brought up outside openrc on Alpine VMs.
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

# --- multi-mode attacker (runs ON app host when /tmp/compromised-* flag present) ---
# Each mode targets a specific Suricata SID. Flag files toggle behaviour from MGT
# scenario controllers (compromise-app-*.sh).
cat > /usr/local/bin/attacker-app.sh <<'ATTACKER'
#!/bin/sh
# Burst — 100 parallel SYN APP→DB:5432 in seconds → SID 9000031 (>100/60s)
if [ -f /tmp/compromised-burst ]; then
    logger -t "attacker-app" "burst mode active: APP->DB rate flood"
    i=0
    while [ $i -lt 100 ]; do
        echo "SELECT 1" | nc -w 1 10.1.200.10 5432 >/dev/null 2>&1 &
        i=$((i + 1))
    done
    wait
fi

# Bulk — repeated heavy JOIN query triggering DB large reply → SID 9000032 (dsize>4096)
if [ -f /tmp/compromised-bulk ]; then
    logger -t "attacker-app" "bulk mode active: heavy JOIN extraction"
    i=0
    while [ $i -lt 15 ]; do
        echo "SELECT * FROM users JOIN orders JOIN sessions JOIN logs" | nc -w 2 10.1.200.10 5432 >/dev/null 2>&1
        i=$((i + 1))
    done
fi

# SQL — destructive patterns → SID 9000033 (content match)
if [ -f /tmp/compromised-sql ]; then
    logger -t "attacker-app" "sql mode active: destructive SQL"
    echo "DROP TABLE users" | nc -w 2 10.1.200.10 5432 >/dev/null 2>&1
    echo "TRUNCATE orders"  | nc -w 2 10.1.200.10 5432 >/dev/null 2>&1
fi

# SSH — cross-tier SSH attempts → SID 9000035 (workload-to-workload SSH)
if [ -f /tmp/compromised-ssh ]; then
    logger -t "attacker-app" "ssh mode active: cross-tier SSH probe"
    nc -w 2 10.1.200.10 22 </dev/null >/dev/null 2>&1   # APP → DB:22
    nc -w 2 10.1.100.10 22 </dev/null >/dev/null 2>&1   # APP → WEB:22
fi
ATTACKER
chmod +x /usr/local/bin/attacker-app.sh

# Cron: baseline noise every minute + attacker poll every minute (with 30s offset)
cat > /etc/crontabs/root <<'CRON'
* * * * * /usr/local/bin/baseline-noise.sh
* * * * * /usr/local/bin/attacker-app.sh
* * * * * sleep 30; /usr/local/bin/attacker-app.sh
CRON

rc-update add app-server default 2>&1 | tail -1
# Start app-server directly (bypassing openrc net dependency)
killall -9 python3 2>/dev/null || true
pkill -9 -f app-server.py 2>/dev/null || true
sleep 2
nohup /usr/local/bin/app-server.py > /var/log/app-server.log 2>&1 &
sleep 2
rc-update add crond default 2>&1 | tail -1
service crond restart

sleep 2
curl -sf http://localhost:8080/health && echo "← app :8080 OK" || echo "← app FAIL"
curl -sf http://localhost:8080/api/data | head -c 60 && echo
echo "[app] DONE — APP server :8080 + baseline noise + multi-mode attacker"
echo "  Normal mode     : baseline-noise.sh fires every minute (APP→DB legit)"
echo "  Compromise modes (touch flag on APP host):"
echo "    /tmp/compromised-burst  → SID 9000031 (APP→DB rate flood)"
echo "    /tmp/compromised-bulk   → SID 9000032 (DB large reply)"
echo "    /tmp/compromised-sql    → SID 9000033 (DROP TABLE / TRUNCATE)"
echo "    /tmp/compromised-ssh    → SID 9000035 (cross-tier SSH probe)"
echo "  Restore: rm /tmp/compromised-*"
