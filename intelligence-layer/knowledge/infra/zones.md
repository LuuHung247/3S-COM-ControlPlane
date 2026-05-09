# Trust Zones

Four trust zones partition the datacenter fabric. Each zone has its own CIDR, VLAN,
SVI gateway, trust posture, and criticality. The agent maps every alert IP to a zone
via CIDR membership; zone-pair determines the policy verdict (see `policy-matrix.md`).

## WEB — Public-facing web tier serving HTTP for end users (north-south ingress)

CIDR `10.1.100.0/24` on `LEAF-1` (VLAN 100, SVI 10.1.100.1). Trust level: **untrusted**, criticality: **high**.

```yaml
name: WEB
cidr: 10.1.100.0/24
leaf: LEAF-1
vlan: 100
svi_gateway: 10.1.100.1
purpose: Public-facing web tier serving HTTP for end users (north-south ingress)
trust_level: untrusted
criticality: high
```

## DB — Database tier holding persistent application state and sensitive data

CIDR `10.1.200.0/24` on `LEAF-1` (VLAN 200, SVI 10.1.200.1). Trust level: **crown-jewel**, criticality: **critical**.

```yaml
name: DB
cidr: 10.1.200.0/24
leaf: LEAF-1
vlan: 200
svi_gateway: 10.1.200.1
purpose: Database tier holding persistent application state and sensitive data
trust_level: crown-jewel
criticality: critical
```

## APP — Business-logic / application tier mediating between WEB and DB

CIDR `10.2.100.0/24` on `LEAF-2` (VLAN 100, SVI 10.2.100.1). Trust level: **trusted-internal**, criticality: **high**.

```yaml
name: APP
cidr: 10.2.100.0/24
leaf: LEAF-2
vlan: 100
svi_gateway: 10.2.100.1
purpose: Business-logic / application tier mediating between WEB and DB
trust_level: trusted-internal
criticality: high
```

## MGT — Management plane for monitoring, audit, and configuration

CIDR `10.2.50.0/24` on `LEAF-2` (VLAN 300, SVI 10.2.50.1). Trust level: **privileged**, criticality: **critical**.

```yaml
name: MGT
cidr: 10.2.50.0/24
leaf: LEAF-2
vlan: 300
svi_gateway: 10.2.50.1
purpose: Management plane for monitoring, audit, and configuration. Universal access by compliance design.
trust_level: privileged
criticality: critical
```
