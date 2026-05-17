#!/bin/sh
# Yatesbury scenario controllers — Alpine-5 MGT host (10.2.50.10)
# Paste-friendly: copy entire content + paste vào console telnet :5016.
# Pattern: SSH vào target host(s) → touch flag file → attacker cron picks up.

set -e

echo "=== [yates/mgt] Installing scenario controllers on MGT (10.2.50.10) ==="

mkdir -p /root/scenario

# ─────────────────────────────────────────────────────────────────────────
# compromise-yates-vscan.sh — single-host vertical scan
# ─────────────────────────────────────────────────────────────────────────
cat > /root/scenario/compromise-yates-vscan.sh <<'SCRIPT'
#!/bin/sh
echo "[scenario] yates vertical port scan — APP scans DB ports"
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 root@10.2.100.10 \
    'touch /tmp/compromised-yates-vscan; echo "vscan armed on APP"'
echo "[scenario] expect SID 9000040 within 60s (threshold 20 SYN/30s)"
SCRIPT
chmod +x /root/scenario/compromise-yates-vscan.sh

# ─────────────────────────────────────────────────────────────────────────
# compromise-yates-synflood.sh — single-source SYN flood DoS
# ─────────────────────────────────────────────────────────────────────────
cat > /root/scenario/compromise-yates-synflood.sh <<'SCRIPT'
#!/bin/sh
echo "[scenario] yates SYN flood DoS — APP floods DB:5432"
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 root@10.2.100.10 \
    'touch /tmp/compromised-yates-synflood; echo "synflood armed on APP"'
echo "[scenario] expect SID 9000043 within 60s (threshold 200 SYN/10s)"
SCRIPT
chmod +x /root/scenario/compromise-yates-synflood.sh

# ─────────────────────────────────────────────────────────────────────────
# compromise-yates-synddos.sh — coordinated multi-source SYN DDoS
# ─────────────────────────────────────────────────────────────────────────
cat > /root/scenario/compromise-yates-synddos.sh <<'SCRIPT'
#!/bin/sh
echo "[scenario] yates SYN DDoS — APP + WEB jointly flood DB:5432"
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 root@10.2.100.10 \
    'touch /tmp/compromised-yates-synflood /tmp/compromised-yates-synddos'
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 root@10.1.100.10 \
    'touch /tmp/compromised-yates-synddos; echo "synddos armed on WEB"'
echo "[scenario] expect SID 9000044 ×2 (per-src) within 60s"
SCRIPT
chmod +x /root/scenario/compromise-yates-synddos.sh

# ─────────────────────────────────────────────────────────────────────────
# compromise-yates-udpddos.sh — coordinated multi-source UDP flood
# ─────────────────────────────────────────────────────────────────────────
cat > /root/scenario/compromise-yates-udpddos.sh <<'SCRIPT'
#!/bin/sh
echo "[scenario] yates UDP DDoS — APP + WEB UDP flood DB:53"
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 root@10.2.100.10 \
    'touch /tmp/compromised-yates-udpddos; echo "udpddos armed on APP"' || true
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 root@10.1.100.10 \
    'touch /tmp/compromised-yates-udpddos; echo "udpddos armed on WEB"'
echo "[scenario] expect SID 9000045 within 60s (threshold 500 UDP/10s by_dst)"
SCRIPT
chmod +x /root/scenario/compromise-yates-udpddos.sh

# ─────────────────────────────────────────────────────────────────────────
# compromise-yates-distscan.sh — distributed scan across srcs
# ─────────────────────────────────────────────────────────────────────────
cat > /root/scenario/compromise-yates-distscan.sh <<'SCRIPT'
#!/bin/sh
echo "[scenario] yates distributed TCP scan — APP + WEB probe key ports"
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 root@10.2.100.10 \
    'touch /tmp/compromised-yates-monkey; echo "distscan-src armed on APP (via monkey)"' || true
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 root@10.1.100.10 \
    'touch /tmp/compromised-yates-distscan; echo "distscan armed on WEB"'
echo "[scenario] expect SID 9000041 per-src within 60s"
SCRIPT
chmod +x /root/scenario/compromise-yates-distscan.sh

# ─────────────────────────────────────────────────────────────────────────
# compromise-yates-monkey.sh — infection monkey chain
# ─────────────────────────────────────────────────────────────────────────
cat > /root/scenario/compromise-yates-monkey.sh <<'SCRIPT'
#!/bin/sh
echo "[scenario] yates infection monkey chain — APP scans + probes exploit ports"
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 root@10.2.100.10 \
    'touch /tmp/compromised-yates-monkey; echo "monkey armed on APP"'
echo "[scenario] expect SID 9000040 (scan) + SID 9000052 (exploit-port probe) chain"
SCRIPT
chmod +x /root/scenario/compromise-yates-monkey.sh

# ─────────────────────────────────────────────────────────────────────────
# compromise-yates-c2.sh — C2 beacon to external
# ─────────────────────────────────────────────────────────────────────────
cat > /root/scenario/compromise-yates-c2.sh <<'SCRIPT'
#!/bin/sh
echo "[scenario] yates C2 beacon — APP heartbeats to 8.8.8.8:443"
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 root@10.2.100.10 \
    'touch /tmp/compromised-yates-c2; echo "c2 armed on APP"'
echo "[scenario] expect SID 9000046 within 5 min (threshold 5 small SYN/300s)"
SCRIPT
chmod +x /root/scenario/compromise-yates-c2.sh

# ─────────────────────────────────────────────────────────────────────────
# compromise-yates-sqli.sh — SQL injection content patterns
# ─────────────────────────────────────────────────────────────────────────
cat > /root/scenario/compromise-yates-sqli.sh <<'SCRIPT'
#!/bin/sh
echo "[scenario] yates SQL injection — APP fires UNION/OR-1=1/DROP-TABLE to DB:5432"
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 root@10.2.100.10 \
    'touch /tmp/compromised-yates-sqli; echo "sqli armed on APP"'
echo "[scenario] expect SIDs 9000048/9000049/9000050 within 60s"
SCRIPT
chmod +x /root/scenario/compromise-yates-sqli.sh

# ─────────────────────────────────────────────────────────────────────────
# restore-yates.sh — disarm all yates scenarios across hosts
# ─────────────────────────────────────────────────────────────────────────
cat > /root/scenario/restore-yates.sh <<'SCRIPT'
#!/bin/sh
echo "[scenario] restoring all yates flags across APP + WEB"
for h in 10.2.100.10 10.1.100.10; do
  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 root@$h \
      'rm -f /tmp/compromised-yates-* 2>/dev/null; echo "yates flags cleared on '$h'"'
done
echo "[scenario] all yates scenarios disarmed"
SCRIPT
chmod +x /root/scenario/restore-yates.sh

# ─────────────────────────────────────────────────────────────────────────
# Verify install
# ─────────────────────────────────────────────────────────────────────────
echo
echo "=== Installed scenario controllers ==="
ls -la /root/scenario/compromise-yates-*.sh /root/scenario/restore-yates.sh
echo
echo "=== DONE: MGT yatesbury controllers installed ==="
echo "Usage:"
echo "  sh /root/scenario/compromise-yates-vscan.sh       # trigger vertical scan"
echo "  sh /root/scenario/compromise-yates-synflood.sh    # trigger SYN flood DoS"
echo "  sh /root/scenario/compromise-yates-synddos.sh     # trigger SYN DDoS (2 srcs)"
echo "  sh /root/scenario/compromise-yates-udpddos.sh     # trigger UDP DDoS"
echo "  sh /root/scenario/compromise-yates-distscan.sh    # trigger distributed scan"
echo "  sh /root/scenario/compromise-yates-monkey.sh      # trigger infection monkey"
echo "  sh /root/scenario/compromise-yates-c2.sh          # trigger C2 beacon"
echo "  sh /root/scenario/compromise-yates-sqli.sh        # trigger SQL injection"
echo "  sh /root/scenario/restore-yates.sh                # disarm all"
