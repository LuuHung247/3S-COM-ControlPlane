# Leaf Switches (enforcement points)

Four SONiC LEAF switches run iptables FORWARD chains; agent-pushed rules land here. Each
LEAF owns the SVIs for its two attached zones. Cross-LEAF policy is defense-in-depth:
SF pushes the same ruleset to ALL 4 LEAFs so source-routing bypass at one LEAF still
hits enforcement at another. ECMP is balanced over 2 SPINEs — no single point of failure
in the underlay.

Mgmt subnet is `192.168.122.0/24` (libvirt virbr0). Each LEAF mgmt IP listens for gNMI
mTLS on `:9339` for SF → nos-acl-bridge → ConfigDB + iptables enforcement.

## LEAF-1

Mgmt IP `192.168.122.20`. Zones: WEB, DB-OLTP. Role: Enforcement point for WEB + DB-OLTP zones (LEAF-1 receives full 8×8 ruleset via SF; defense-in-depth)

```yaml
name: LEAF-1
mgmt_ip: 192.168.122.20
gnmi_port: 9339
zones:
- WEB
- DB-OLTP
role: Enforcement point for WEB + DB-OLTP zones. Receives full 8x8 ruleset from SF for defense-in-depth.
```

## LEAF-2

Mgmt IP `192.168.122.21`. Zones: APP-CORE, MGT. Role: Enforcement point for APP-CORE + MGT zones (same full ruleset)

```yaml
name: LEAF-2
mgmt_ip: 192.168.122.21
gnmi_port: 9339
zones:
- APP-CORE
- MGT
role: Enforcement point for APP-CORE + MGT zones. Receives full 8x8 ruleset from SF.
```

## LEAF-3

Mgmt IP `192.168.122.22`. Zones: APP-GW, DB-ANALYTICS. Role: Enforcement point for APP-GW + DB-ANALYTICS zones (V2 expansion)

```yaml
name: LEAF-3
mgmt_ip: 192.168.122.22
gnmi_port: 9339
zones:
- APP-GW
- DB-ANALYTICS
role: Enforcement point for APP-GW + DB-ANALYTICS zones. V2 expansion. Receives full 8x8 ruleset from SF.
```

## LEAF-4

Mgmt IP `192.168.122.23`. Zones: WORKER, MONITORING. Role: Enforcement point for WORKER + MONITORING zones (V2 expansion)

```yaml
name: LEAF-4
mgmt_ip: 192.168.122.23
gnmi_port: 9339
zones:
- WORKER
- MONITORING
role: Enforcement point for WORKER + MONITORING zones. V2 expansion. Receives full 8x8 ruleset from SF.
```
