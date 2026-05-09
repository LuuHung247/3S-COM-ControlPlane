# Leaf Switches (enforcement points)

Two SONiC leafs run iptables FORWARD chains; agent-pushed rules land here. Each leaf
owns the SVIs for its attached zones. Cross-leaf policy is defense-in-depth: same
rule applied on both leafs so source-routing bypass at one leaf still hits the other.

## LEAF-1

Mgmt IP `192.168.122.20`. Zones: WEB, DB. Role: Enforcement point for WEB and DB zones (intra-leaf and cross-leaf rules)

```yaml
name: LEAF-1
mgmt_ip: 192.168.122.20
zones:
- WEB
- DB
role: Enforcement point for WEB and DB zones (intra-leaf and cross-leaf rules)
```

## LEAF-2

Mgmt IP `192.168.122.21`. Zones: APP, MGT. Role: Enforcement point for APP and MGT zones

```yaml
name: LEAF-2
mgmt_ip: 192.168.122.21
zones:
- APP
- MGT
role: Enforcement point for APP and MGT zones
```
