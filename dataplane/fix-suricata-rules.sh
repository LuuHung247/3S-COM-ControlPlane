#!/bin/sh
# Fix Suricata false positives — paste into Suricata console
# telnet 112.137.129.232:5018  (login: root, no password)
#
# Root cause: tc mirred ingress captures RESPONSE traffic from DB→APP
# when APP connects to DB:5432. IDS only sees 1 direction, no flow context
# → Suricata flags DB:5432→APP as "DB initiating outbound" (SID 9000002).
#
# Fix: narrow SID 9000002 destination to EXTERNAL IPs only (not internal zones)

RULES=/etc/suricata/rules/3s-nos.rules

echo "=== Current SID 9000002 rule ==="
grep "9000002" $RULES

echo
echo "=== Applying fix ==="

# Backup
cp $RULES ${RULES}.bak.$(date +%s)

# Fix SID 9000002: DB outbound → only fire on external destinations (not internal zones)
# Before: src=10.1.200.0/24 dst=!10.1.200.0/24  (fires on DB→APP which is response traffic)
# After:  src=10.1.200.0/24 dst=![all internal]  (only fires on DB→external = real exfil)
sed -i 's|10\.1\.200\.0/24 any -> !10\.1\.200\.0/24 any|10.1.200.0/24 any -> ![10.1.200.0/24,10.1.100.0/24,10.2.100.0/24,10.2.50.0/24] any|g' $RULES

echo "=== After fix ==="
grep "9000002" $RULES

echo
echo "=== Reloading Suricata rules (no restart needed) ==="
kill -USR2 $(cat /var/run/suricata.pid 2>/dev/null || pgrep suricata) 2>/dev/null && echo "Reload OK" || echo "Reload FAIL — check: pgrep suricata"

echo
echo "=== Done. Test: DB response to APP should no longer fire SID 9000002 ==="
