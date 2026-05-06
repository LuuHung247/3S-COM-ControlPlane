#!/bin/sh
# Redeploy IDS stack on Alpine ISO VM after reboot.
# Run from this directory on the VM (e.g. after scp'ing the bundle).
set -e
cd "$(dirname "$0")"

apk add --no-cache python3

install -m 755 ids-api.py            /usr/local/bin/ids-api.py
install -m 755 ids-api.openrc        /etc/init.d/ids-api
install -m 755 suricata.openrc       /etc/init.d/suricata-zt
install -m 644 suricata-zt.yaml      /etc/suricata/suricata-zt.yaml
install -m 644 rules/zt-lab.rules    /etc/suricata/rules/zt-lab.rules

mkdir -p /var/log/suricata

rc-update add suricata-zt default 2>/dev/null || true
rc-update add ids-api     default 2>/dev/null || true

rc-service suricata-zt start
sleep 5
rc-service ids-api start

sleep 2
rc-service suricata-zt status
rc-service ids-api status
ss -ltn 2>/dev/null | grep 8765 || echo "WARN: api not listening on 8765"
