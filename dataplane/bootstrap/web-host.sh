#!/bin/sh
# Bootstrap Alpine-1 (WEB zone, 10.1.100.10)
# Normal:     nginx :80 serves e-commerce frontend
# Compromised (multi-mode via flag files):
#   /tmp/compromised        → legacy lateral WEB→DB + WEB→MGT (SID 9000001)
#   /tmp/compromised-burst  → 250 connections WEB→APP:8080/min (SID 9000030)
# Paste into: telnet 112.137.129.232:5008  (login: root, no password)
set -e

echo "[web] installing packages"
apk add --no-cache nginx curl busybox-extras 2>&1 | tail -3

# --- cleanup legacy artifacts from old web-host.sh (pre-refactor) ---
# Old bootstrap used `nc -l -p 80` via /usr/local/bin/web-server.sh + cron selfmon.
# Stop cron, kill any stray nc on :80, remove old scripts before reinstall.
service crond stop 2>&1 | tail -1 || true
killall -9 nc 2>/dev/null || true
pkill -9 -f 'web-server.sh' 2>/dev/null || true
pkill -9 -f 'web-selfmon.sh' 2>/dev/null || true
rm -f /usr/local/bin/web-server.sh /usr/local/bin/web-selfmon.sh
sleep 1

# --- nginx setup ---
mkdir -p /var/www/html /run/nginx
cat > /var/www/html/index.html <<'HTML'
<!DOCTYPE html>
<html><head><title>Acme Shop — WEB</title></head>
<body>
  <h1>Acme E-Commerce Frontend</h1>
  <p>Zone: WEB | Host: Alpine-1 | IP: 10.1.100.10</p>
  <p>Upstream: APP 10.2.100.10:8080</p>
</body></html>
HTML

cat > /etc/nginx/http.d/default.conf <<'NGINX'
server {
    listen 80 default_server;
    root /var/www/html;
    index index.html;
    location /health { return 200 "web-ok\n"; add_header Content-Type text/plain; }
    location /api/ {
        proxy_pass http://10.2.100.10:8080/;
        proxy_connect_timeout 3s;
        proxy_read_timeout 5s;
    }
}
NGINX

rc-update add nginx default 2>&1 | tail -1
# nginx openrc unit has `need net` — bypass since networking is up out-of-band on
# Alpine VMs. Run nginx binary directly (it daemonizes itself).
nginx -s stop 2>/dev/null || true
pkill -9 nginx 2>/dev/null || true
sleep 1
nginx -t 2>&1 | tail -3
nginx

# --- attacker script (runs ON web host simulating post-compromise lateral) ---
# Two modes selected by flag file:
#   /tmp/compromised       → legacy lateral WEB→DB + WEB→MGT (SID 9000001)
#   /tmp/compromised-burst → high-rate WEB→APP:8080 spam (SID 9000030)
cat > /usr/local/bin/attacker-web.sh <<'ATTACKER'
#!/bin/sh
# Legacy: lateral movement WEB→DB:5432 + escalation WEB→MGT:22 (T1021/T1078)
if [ -f /tmp/compromised ]; then
    logger -t "attacker-web" "lateral movement attempt: WEB->DB:5432"
    nc -w 2 10.1.200.10 5432 </dev/null >/dev/null 2>&1
    nc -w 2 10.2.50.10 22  </dev/null >/dev/null 2>&1
fi

# Burst: 250 parallel SYN to APP:8080 → SID 9000030 (>200/60s threshold)
if [ -f /tmp/compromised-burst ]; then
    logger -t "attacker-web" "burst mode active: WEB->APP rate flood"
    i=0
    while [ $i -lt 250 ]; do
        nc -w 1 10.2.100.10 8080 </dev/null >/dev/null 2>&1 &
        i=$((i + 1))
    done
    wait
fi
ATTACKER
chmod +x /usr/local/bin/attacker-web.sh

# Cron: run every 90s (cron min resolution = 1min, so run twice with sleep offset)
# Baseline shopper — simulate user browsing flow WEB → APP:8080 each cron tick.
# Without this WEB host is silent on Monitor (FE marks zone offline). Matches
# zt-web-app-allow path on LEAF; legitimate traffic, not attack.
cat > /usr/local/bin/baseline-shopper.sh <<'SHOPPER'
#!/bin/sh
curl -sf --max-time 3 http://10.2.100.10:8080/health >> /var/log/baseline-shopper.log 2>&1
SHOPPER
chmod +x /usr/local/bin/baseline-shopper.sh

cat > /etc/crontabs/root <<'CRON'
* * * * * /usr/local/bin/attacker-web.sh
* * * * * sleep 45; /usr/local/bin/attacker-web.sh
* * * * * /usr/local/bin/baseline-shopper.sh
* * * * * sleep 30; /usr/local/bin/baseline-shopper.sh
CRON

rc-update add crond default 2>&1 | tail -1
service crond restart

sleep 1
curl -sf http://localhost/health && echo "← health OK" || echo "← health FAIL"
echo "[web] DONE"
echo "  Normal mode      : nginx serving on :80"
echo "  Legacy compromise: touch /tmp/compromised        → WEB→DB + WEB→MGT (SID 9000001)"
echo "  Burst compromise : touch /tmp/compromised-burst  → WEB→APP flood   (SID 9000030)"
echo "  Restore: rm /tmp/compromised /tmp/compromised-burst"
