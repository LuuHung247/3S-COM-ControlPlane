# Workload Assets

Each zone hosts exactly one production workload. Single-host-per-zone simplifies
tenant identity: zone CIDR maps 1:1 to a host. Each asset declares its services,
expected traffic neighbors, and blast-radius prose for both 'compromised' and
'blocked' counterfactuals — agents use these to weigh containment vs availability.

## web-01 (10.1.100.10)

**Zone**: WEB  ·  **Tier**: presentation tier  ·  **Criticality**: high  ·  **Data**: public  ·  **Owner**: platform

**Role**: Public-facing HTTP frontend serving end-user requests

**If compromised**:

> Adversary gains foothold on Internet-exposed tier. Pivots toward APP tier through legitimate WEB→APP path, or attempts direct DB access bypassing application controls.

**If blocked**:

> End-user-facing HTTP service goes dark. Outbound proxy to APP tier breaks. User experience fully degraded.

```yaml
ip: 10.1.100.10
hostname: web-01
zone: WEB
tier: presentation tier
role: Public-facing HTTP frontend serving end-user requests
criticality: high
data_classification: public
services:
- port: 80
  proto: tcp
  name: http
  facing: external
  purpose: Serves HTTP banner content to external users — north-south ingress entry point
- port: 22
  proto: tcp
  name: sshd
  facing: internal-mgt-only
  purpose: Operational SSH access restricted to management plane
expected_inbound_sources:
- external
- MGT
expected_outbound_destinations:
- 10.2.100.10:8080 (APP tier API)
if_compromised_impact: Adversary gains foothold on Internet-exposed tier. Pivots toward APP tier through
  legitimate WEB→APP path, or attempts direct DB access bypassing application controls.
if_blocked_impact: End-user-facing HTTP service goes dark. Outbound proxy to APP tier breaks. User experience
  fully degraded.
owner_team: platform
```

## db-01 (10.1.200.10)

**Zone**: DB  ·  **Tier**: data tier  ·  **Criticality**: critical  ·  **Data**: confidential  ·  **Owner**: data

**Role**: SQL backend serving OLTP transactions for the application tier

**If compromised**:

> Crown-jewel breach. Adversary has direct read/write to persistent business state. Likely follow-up: data exfiltration over outbound channel (C2 beacon, DNS tunnel, or SSH covert tunnel).

**If blocked**:

> Full application outage. APP tier loses transactional backend. All user-facing operations requiring DB read/write fail. Highest-cost block target.

```yaml
ip: 10.1.200.10
hostname: db-01
zone: DB
tier: data tier
role: SQL backend serving OLTP transactions for the application tier
criticality: critical
data_classification: confidential
services:
- port: 5432
  proto: tcp
  name: postgresql-wire
  facing: internal-app-only
  purpose: Serves SQL transactions (SELECT/INSERT/UPDATE) issued by APP tier
- port: 22
  proto: tcp
  name: sshd
  facing: internal-mgt-only
  purpose: Operational SSH restricted to management plane for compliance audit
expected_inbound_sources:
- APP
- MGT
expected_outbound_destinations: []
if_compromised_impact: 'Crown-jewel breach. Adversary has direct read/write to persistent business state.
  Likely follow-up: data exfiltration over outbound channel (C2 beacon, DNS tunnel, or SSH covert tunnel).'
if_blocked_impact: Full application outage. APP tier loses transactional backend. All user-facing operations
  requiring DB read/write fail. Highest-cost block target.
owner_team: data
```

## app-01 (10.2.100.10)

**Zone**: APP  ·  **Tier**: application tier  ·  **Criticality**: high  ·  **Data**: internal  ·  **Owner**: platform

**Role**: Business logic tier bridging WEB requests to DB transactions

**If compromised**:

> Adversary on application tier has legitimate path to DB. Risk: SQL exfiltration via application-mediated channel, or pivot to MGT zone for credential abuse.

**If blocked**:

> Application logic tier offline. WEB requests cannot reach DB. End-user operations fail. Cascade outage to presentation tier.

```yaml
ip: 10.2.100.10
hostname: app-01
zone: APP
tier: application tier
role: Business logic tier bridging WEB requests to DB transactions
criticality: high
data_classification: internal
services:
- port: 8080
  proto: tcp
  name: http-api
  facing: any
  purpose: Application HTTP API consumed by WEB tier proxy and MGT health probes
- port: 22
  proto: tcp
  name: sshd
  facing: internal-mgt-only
  purpose: Operational SSH for compliance audit and log retrieval
expected_inbound_sources:
- WEB
- MGT
expected_outbound_destinations:
- 10.1.200.10:5432 (DB tier OLTP)
if_compromised_impact: 'Adversary on application tier has legitimate path to DB. Risk: SQL exfiltration
  via application-mediated channel, or pivot to MGT zone for credential abuse.'
if_blocked_impact: Application logic tier offline. WEB requests cannot reach DB. End-user operations fail.
  Cascade outage to presentation tier.
owner_team: platform
```

## mgt-01 (10.2.50.10)

**Zone**: MGT  ·  **Tier**: management plane  ·  **Criticality**: critical  ·  **Data**: restricted  ·  **Owner**: ops

**Role**: Operational host running compliance audit, health scrape, log collection

**If compromised**:

> TOTAL SYSTEM COMPROMISE. Management plane has universal access by design. Adversary on MGT can reach every zone, every host, with legitimate credentials. Lateral movement is unconstrained.

**If blocked**:

> Loss of compliance audit, health monitoring, log collection. Operational visibility blind. Agent itself loses ability to verify network state from MGT vantage. MUST NEVER be blocked by automated agent.

```yaml
ip: 10.2.50.10
hostname: mgt-01
zone: MGT
tier: management plane
role: Operational host running compliance audit, health scrape, log collection
criticality: critical
data_classification: restricted
services:
- port: 22
  proto: tcp
  name: sshd
  facing: internal-mgt-only
  purpose: Operational entry point — only listening service; no application workload
expected_inbound_sources:
- MGT
expected_outbound_destinations:
- 10.1.100.10:80 (WEB scrape)
- 10.1.100.10:22 (WEB audit)
- 10.2.100.10:8080 (APP scrape)
- 10.2.100.10:22 (APP audit + logpull)
- 10.1.200.10:5432 (DB scrape)
- 10.1.200.10:22 (DB audit)
if_compromised_impact: TOTAL SYSTEM COMPROMISE. Management plane has universal access by design. Adversary
  on MGT can reach every zone, every host, with legitimate credentials. Lateral movement is unconstrained.
if_blocked_impact: Loss of compliance audit, health monitoring, log collection. Operational visibility
  blind. Agent itself loses ability to verify network state from MGT vantage. MUST NEVER be blocked by
  automated agent.
owner_team: ops
```
