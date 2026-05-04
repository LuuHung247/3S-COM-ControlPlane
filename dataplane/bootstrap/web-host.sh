#!/bin/sh
# Bootstrap Alpine-1 (WEB zone, 10.1.100.10)
# Normal:     nginx :80 serves e-commerce frontend
# Compromised: touch /tmp/compromised → attacker cron lateral WEB→DB every 90s
# Paste into: telnet 112.137.129.232:5008  (login: root, no password)
set -e

echo "[web] installing packages"
apk add --no-cache nginx curl busybox-extras 2>&1 | tail -3

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
service nginx restart

# --- attacker script (runs ON web host simulating post-compromise lateral) ---
cat > /usr/local/bin/attacker-web.sh <<'ATTACKER'
#!/bin/sh
# Only runs when /tmp/compromised exists
# Simulates: attacker who pwned WEB tries to reach DB directly (T1021 Remote Services)
[ -f /tmp/compromised ] || exit 0
logger -t "attacker-web" "lateral movement attempt: WEB→DB:5432"
nc -w 2 10.1.200.10 5432 < /dev/null 2>&1
# Also try WEB→MGT SSH escalation (T1078)
nc -w 2 10.2.50.10 22 < /dev/null 2>&1
ATTACKER
chmod +x /usr/local/bin/attacker-web.sh

# Cron: run every 90s (cron min resolution = 1min, so run twice with sleep offset)
cat > /etc/crontabs/root <<'CRON'
* * * * * /usr/local/bin/attacker-web.sh
* * * * * sleep 45; /usr/local/bin/attacker-web.sh
CRON

rc-update add crond default 2>&1 | tail -1
service crond restart

sleep 1
curl -sf http://localhost/health && echo "← health OK" || echo "← health FAIL"
echo "[web] DONE"
echo "  Normal mode : nginx serving on :80"
echo "  Attack mode : touch /tmp/compromised  (to deactivate: rm /tmp/compromised)"
