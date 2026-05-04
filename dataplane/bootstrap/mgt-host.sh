#!/bin/sh
# Bootstrap Alpine-5 (MGT zone, 10.2.50.10)
# Role: management — SSH audit into all hosts every 2min (triggers SID 9000020 MGT audit)
# Also: scenario controller — SSH into WEB/DB and touch /tmp/compromised to trigger attacks
# Paste into: telnet 112.137.129.232:5016  (login: root, no password)
set -e

echo "[mgt] installing packages"
apk add --no-cache openssh-client curl busybox-extras nmap 2>&1 | tail -3

# SSH key for passwordless management (lab only)
if [ ! -f /root/.ssh/id_rsa ]; then
  mkdir -p /root/.ssh && chmod 700 /root/.ssh
  ssh-keygen -t rsa -N "" -f /root/.ssh/id_rsa -q
fi
cat /root/.ssh/id_rsa.pub

cat > /root/.ssh/config <<'SSHCFG'
Host 10.1.100.10 10.1.200.10 10.2.100.10
  StrictHostKeyChecking no
  ConnectTimeout 3
  User root
SSHCFG
chmod 600 /root/.ssh/config

# --- management audit (legitimate MGT behavior, triggers SID 9000020) ---
cat > /usr/local/bin/mgt-audit.sh <<'AUDIT'
#!/bin/sh
# Normal management: SSH into each host to check status
# This traffic pattern (MGT→WEB/DB/APP) is ALLOWED per policy
# SID 9000020 fires on MGT zone access — P4 log_only audit trail
for HOST in 10.1.100.10 10.1.200.10 10.2.100.10; do
  ssh -o BatchMode=yes $HOST 'uptime; df -h / | tail -1' >> /var/log/mgt-audit.log 2>&1
done
logger -t mgt-audit "audit cycle done"
AUDIT
chmod +x /usr/local/bin/mgt-audit.sh

cat > /etc/crontabs/root <<'CRON'
*/2 * * * * /usr/local/bin/mgt-audit.sh
CRON

rc-update add crond default 2>&1 | tail -1
service crond restart

# --- scenario controller scripts (run manually for demo) ---
mkdir -p /root/scenario

cat > /root/scenario/compromise-web.sh <<'SC'
#!/bin/sh
# Simulate attacker gaining foothold on WEB host
# WEB cron will then auto-attempt WEB→DB:5432 (SID 9000001) and WEB→MGT:22 (SID 9000004)
echo "[scenario] compromising WEB host 10.1.100.10"
ssh root@10.1.100.10 'touch /tmp/compromised; echo "WEB compromised"'
echo "[scenario] attack cron active on WEB — watch logs:"
echo "  curl http://localhost:8767/stream"
SC

cat > /root/scenario/compromise-db.sh <<'SC'
#!/bin/sh
# Simulate attacker gaining foothold on DB host
# DB cron will then auto-attempt DB→8.8.8.8:443 (SID 9000002)
echo "[scenario] compromising DB host 10.1.200.10"
ssh root@10.1.200.10 'touch /tmp/compromised; echo "DB compromised"'
echo "[scenario] exfil cron active on DB"
SC

cat > /root/scenario/restore-web.sh <<'SC'
#!/bin/sh
echo "[scenario] restoring WEB host (removing attacker persistence)"
ssh root@10.1.100.10 'rm -f /tmp/compromised; echo "WEB restored"'
SC

cat > /root/scenario/restore-db.sh <<'SC'
#!/bin/sh
echo "[scenario] restoring DB host"
ssh root@10.1.200.10 'rm -f /tmp/compromised; echo "DB restored"'
SC

cat > /root/scenario/status.sh <<'SC'
#!/bin/sh
echo "=== DCN Status ==="
for HOST in 10.1.100.10 10.1.200.10 10.2.100.10; do
  STATUS=$(ssh -o BatchMode=yes $HOST '[ -f /tmp/compromised ] && echo COMPROMISED || echo clean' 2>/dev/null || echo "unreachable")
  echo "  $HOST: $STATUS"
done
SC

chmod +x /root/scenario/*.sh

echo
echo "[mgt] DONE"
echo
echo "  Audit cron: every 2min SSH→all hosts (triggers SID 9000020)"
echo
echo "  SSH key — copy this to /root/.ssh/authorized_keys on WEB/DB/APP hosts:"
echo "  ──────────────────────────────────────────────────────────────────────"
cat /root/.ssh/id_rsa.pub
echo "  ──────────────────────────────────────────────────────────────────────"
echo
echo "  Scenario scripts:"
ls -1 /root/scenario/
echo
echo "  Usage:"
echo "    sh /root/scenario/compromise-web.sh   # WEB bị pwn → lateral WEB→DB"
echo "    sh /root/scenario/compromise-db.sh    # DB bị pwn → exfil DB→internet"
echo "    sh /root/scenario/status.sh           # check compromise state"
echo "    sh /root/scenario/restore-web.sh      # remove attacker persistence"
