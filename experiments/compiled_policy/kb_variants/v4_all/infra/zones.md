# Trust Zones (V2 — 8-zone Clos DCN)

Eight trust zones partition the datacenter fabric across 4 LEAF switches (2 zones per
LEAF). Each zone has its own CIDR, VLAN, SVI gateway, trust posture, and criticality.
The agent maps every alert IP to a zone via CIDR membership; zone-pair determines the
policy verdict (see `policy-matrix.md`). All zones are internal east-west tiers; no DMZ.

Topology layout (V2 As-Deployed):

```
LEAF-1:  WEB (10.1.100/24)        DB-OLTP (10.1.200/24)
LEAF-2:  APP-CORE (10.2.100/24)   MGT (10.2.50/24)
LEAF-3:  APP-GW (10.3.100/24)     DB-ANALYTICS (10.3.200/24)
LEAF-4:  WORKER (10.4.100/24)     MONITORING (10.4.200/24)
```

Legitimate east-west chain:

```
WEB → APP-GW → APP-CORE ─┬─→ WORKER → DB-OLTP → DB-ANALYTICS
                         └─→ DB-OLTP
                         └─→ DB-ANALYTICS
MONITORING → (scrape all except MGT)        MGT → (admin all except itself)
```

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

## DB-OLTP — Online transactional database tier (PostgreSQL-equivalent) — OLTP workload

CIDR `10.1.200.0/24` on `LEAF-1` (VLAN 200, SVI 10.1.200.1). Trust level: **crown-jewel**, criticality: **critical**.

```yaml
name: DB-OLTP
cidr: 10.1.200.0/24
leaf: LEAF-1
vlan: 200
svi_gateway: 10.1.200.1
purpose: Online transactional database tier (PostgreSQL-equivalent) — OLTP workload. Persistent business state.
trust_level: crown-jewel
criticality: critical
```

## APP-CORE — Business-logic / application core mediating between APP-GW and data tier

CIDR `10.2.100.0/24` on `LEAF-2` (VLAN 100, SVI 10.2.100.1). Trust level: **trusted-internal**, criticality: **high**.

```yaml
name: APP-CORE
cidr: 10.2.100.0/24
leaf: LEAF-2
vlan: 100
svi_gateway: 10.2.100.1
purpose: Business-logic / application core. Owns SQL transactions to DB-OLTP, dispatches jobs to WORKER, runs analytics queries to DB-ANALYTICS.
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
purpose: Management plane for monitoring, audit, and configuration. Universal access by compliance design — may SSH any zone (except itself, irrelevant).
trust_level: privileged
criticality: critical
```

## APP-GW — Application gateway / reverse-proxy tier; only legitimate WEB ingress to APP-CORE

CIDR `10.3.100.0/24` on `LEAF-3` (VLAN 100, SVI 10.3.100.1). Trust level: **trusted-internal**, criticality: **high**.

```yaml
name: APP-GW
cidr: 10.3.100.0/24
leaf: LEAF-3
vlan: 100
svi_gateway: 10.3.100.1
purpose: Application gateway. Terminates WEB requests, forwards to APP-CORE. Only allowed source from WEB into app tier — bypasses are policy violations.
trust_level: trusted-internal
criticality: high
```

## DB-ANALYTICS — Analytics / reporting database — read-only sink fed from DB-OLTP + APP-CORE

CIDR `10.3.200.0/24` on `LEAF-3` (VLAN 200, SVI 10.3.200.1). Trust level: **crown-jewel**, criticality: **critical**.

```yaml
name: DB-ANALYTICS
cidr: 10.3.200.0/24
leaf: LEAF-3
vlan: 200
svi_gateway: 10.3.200.1
purpose: Analytics / reporting database. Pure sink — must never initiate outbound (sink-role invariant). Fed by APP-CORE (reports) and DB-OLTP (replication).
trust_level: crown-jewel
criticality: critical
```

## WORKER — Async job worker — consumes dispatch from APP-CORE, writes to DB-OLTP only

CIDR `10.4.100.0/24` on `LEAF-4` (VLAN 100, SVI 10.4.100.1). Trust level: **trusted-internal**, criticality: **medium**.

```yaml
name: WORKER
cidr: 10.4.100.0/24
leaf: LEAF-4
vlan: 100
svi_gateway: 10.4.100.1
purpose: Async worker tier. Receives job dispatch from APP-CORE (port 8082), persists results to DB-OLTP. Must NOT touch DB-ANALYTICS or other tiers.
trust_level: trusted-internal
criticality: medium
```

## MONITORING — Observability tier scraping all data tiers for metrics

CIDR `10.4.200.0/24` on `LEAF-4` (VLAN 200, SVI 10.4.200.1). Trust level: **privileged-readonly**, criticality: **high**.

```yaml
name: MONITORING
cidr: 10.4.200.0/24
leaf: LEAF-4
vlan: 200
svi_gateway: 10.4.200.1
purpose: Observability tier. Scrapes WEB/APP-GW/APP-CORE/WORKER + both DBs for metrics. Read-only by role — never expected to initiate writes. May NOT reach MGT.
trust_level: privileged-readonly
criticality: high
```

## PAYMENTS — Card-payment tokenisation and settlement service (PCI-DSS scope)

CIDR `10.5.100.0/24` on `LEAF-5` (VLAN 100, SVI 10.5.100.1). Trust level: **crown-jewel**, criticality: **critical**.

```yaml
name: PAYMENTS
cidr: 10.5.100.0/24
leaf: LEAF-5
vlan: 100
svi_gateway: 10.5.100.1
purpose: Card-payment tokenisation and settlement (PCI-DSS scope). Called only by APP-CORE; writes settlement records to DB-OLTP.
trust_level: crown-jewel
criticality: critical
```
