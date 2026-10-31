# Workload Assets (V2 — 8 zones × 2 hosts = 16 hosts)

Each zone hosts 2 production hosts (`*-01` at `.10`, `*-02` at `.11`) for resilience.
This file lists one canonical asset per zone (`*-01` at `.10`); the secondary host
mirrors role, criticality, and services. The agent maps every alert IP to a zone via
CIDR membership and uses the zone's blast-radius prose to weigh containment vs
availability.

## web-01 (10.1.100.10)

**Zone**: WEB  ·  **Tier**: presentation tier  ·  **Criticality**: high  ·  **Data**: public  ·  **Owner**: platform

**Role**: Public-facing HTTP frontend serving end-user requests

**If compromised**:

> Adversary gains foothold on Internet-exposed tier. Pivots toward APP-GW through legitimate WEB→APP-GW path. Direct attempts to skip APP-GW (WEB→APP-CORE or WEB→DB) are immediate microsegmentation violations.

**If blocked**:

> End-user-facing HTTP service goes dark. Outbound to APP-GW breaks. User experience fully degraded.

```yaml
ip: 10.1.100.10
hostname: web-01
zone: WEB
tier: presentation tier
role: Public-facing HTTP frontend serving end-user requests
criticality: high
data_classification: public
secondary_host_ip: 10.1.100.11
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
  purpose: Operational SSH access restricted to MGT plane
expected_inbound_sources:
- external
- MGT
- MONITORING
expected_outbound_destinations:
- 10.3.100.10:8080 (APP-GW)
if_compromised_impact: Adversary gains foothold on Internet-exposed tier. Pivots toward APP-GW through
  legitimate WEB→APP-GW path. Direct WEB→APP-CORE or WEB→DB attempts are immediate microsegmentation violations.
if_blocked_impact: End-user-facing HTTP service goes dark. Outbound to APP-GW breaks. User experience
  fully degraded.
owner_team: platform
```

## app-gw-01 (10.3.100.10)

**Zone**: APP-GW  ·  **Tier**: gateway / reverse proxy  ·  **Criticality**: high  ·  **Data**: internal  ·  **Owner**: platform

**Role**: API gateway terminating WEB traffic, forwards to APP-CORE

**If compromised**:

> Adversary on the only legitimate WEB→app-tier hop. Risk: pivot to APP-CORE, then to data tier. Skipping APP-CORE (APP-GW→DB direct) is a hard violation.

**If blocked**:

> WEB cannot reach app tier. Cascade outage to end users. Highest-tier ingress dependency.

```yaml
ip: 10.3.100.10
hostname: app-gw-01
zone: APP-GW
tier: gateway / reverse proxy
role: Terminates WEB ingress; forwards authorized requests to APP-CORE
criticality: high
data_classification: internal
secondary_host_ip: 10.3.100.11
services:
- port: 8080
  proto: tcp
  name: api-gateway
  facing: from-WEB-only
  purpose: HTTP gateway port — receives from WEB, forwards to APP-CORE:8090
- port: 22
  proto: tcp
  name: sshd
  facing: internal-mgt-only
  purpose: Operational SSH restricted to MGT plane
expected_inbound_sources:
- WEB
- MGT
- MONITORING
expected_outbound_destinations:
- 10.2.100.10:8090 (APP-CORE)
if_compromised_impact: 'Adversary on the only legitimate WEB→app-tier hop. Risk: pivot to APP-CORE, then
  to data tier. Skipping APP-CORE (APP-GW→DB direct) is a hard violation.'
if_blocked_impact: WEB cannot reach app tier. Cascade outage to end users. Highest-tier ingress dependency.
owner_team: platform
```

## app-core-01 (10.2.100.10)

**Zone**: APP-CORE  ·  **Tier**: business logic  ·  **Criticality**: high  ·  **Data**: internal  ·  **Owner**: platform

**Role**: Application core — issues SQL to DB-OLTP, dispatches jobs to WORKER, runs reports against DB-ANALYTICS

**If compromised**:

> Adversary on the tier with legitimate access to BOTH databases AND WORKER. Massive blast radius: SQL exfil, job-queue manipulation, lateral to analytics tier. Reverse calls (APP-CORE→WEB or APP-CORE→APP-GW) signal compromise.

**If blocked**:

> Entire business-logic tier offline. WEB requests cannot be processed. Job dispatch and analytics ETL break. Highest-cost block target except DB.

```yaml
ip: 10.2.100.10
hostname: app-core-01
zone: APP-CORE
tier: business logic
role: Application core. Owns SQL transactions to DB-OLTP, dispatches jobs to WORKER, executes report queries against DB-ANALYTICS.
criticality: high
data_classification: internal
secondary_host_ip: 10.2.100.11
services:
- port: 8090
  proto: tcp
  name: core-service
  facing: from-APP-GW-only
  purpose: Core service port — receives from APP-GW, originates SQL/job traffic to data + worker tier
- port: 22
  proto: tcp
  name: sshd
  facing: internal-mgt-only
expected_inbound_sources:
- APP-GW
- MGT
- MONITORING
expected_outbound_destinations:
- 10.1.200.10:5432 (DB-OLTP)
- 10.3.200.10:5432 (DB-ANALYTICS)
- 10.4.100.10:8082 (WORKER)
if_compromised_impact: 'Adversary on the tier with legitimate access to BOTH databases AND WORKER. Massive
  blast radius: SQL exfil, job-queue manipulation, lateral to analytics tier. Reverse calls (APP-CORE→WEB
  or APP-CORE→APP-GW) signal compromise.'
if_blocked_impact: Entire business-logic tier offline. WEB requests cannot be processed. Job dispatch and
  analytics ETL break. Highest-cost block target except DB.
owner_team: platform
```

## worker-01 (10.4.100.10)

**Zone**: WORKER  ·  **Tier**: async worker  ·  **Criticality**: medium  ·  **Data**: internal  ·  **Owner**: platform

**Role**: Async job worker — receives dispatch from APP-CORE, persists results to DB-OLTP

**If compromised**:

> Limited blast radius — WORKER can only legitimately reach DB-OLTP. Any other outbound (WORKER→DB-ANALYTICS, WORKER→APP-GW, WORKER→WEB) is a hard policy violation and clear lateral-movement signal.

**If blocked**:

> Async job processing halts. Backlog accumulates. Downstream services depending on background job completion degrade. Recoverable — not customer-facing.

```yaml
ip: 10.4.100.10
hostname: worker-01
zone: WORKER
tier: async worker
role: Receives job dispatch from APP-CORE, persists results to DB-OLTP
criticality: medium
data_classification: internal
secondary_host_ip: 10.4.100.11
services:
- port: 8082
  proto: tcp
  name: job-intake
  facing: from-APP-CORE-only
  purpose: Job intake port — receives dispatch from APP-CORE
- port: 22
  proto: tcp
  name: sshd
  facing: internal-mgt-only
expected_inbound_sources:
- APP-CORE
- MGT
- MONITORING
expected_outbound_destinations:
- 10.1.200.10:5432 (DB-OLTP only)
if_compromised_impact: Limited blast radius — WORKER can only legitimately reach DB-OLTP. Any other outbound
  (WORKER→DB-ANALYTICS, WORKER→APP-GW, WORKER→WEB) is a hard policy violation and clear lateral-movement
  signal.
if_blocked_impact: Async job processing halts. Backlog accumulates. Downstream services depending on background
  job completion degrade. Recoverable — not customer-facing.
owner_team: platform
```

## db-oltp-01 (10.1.200.10)

**Zone**: DB-OLTP  ·  **Tier**: data tier (transactional)  ·  **Criticality**: critical  ·  **Data**: confidential  ·  **Owner**: data

**Role**: OLTP database backend — receives SQL from APP-CORE + WORKER + MGT + MONITORING. Replicates to DB-ANALYTICS.

**If compromised**:

> Crown-jewel breach (transactional data). Adversary has direct read/write to persistent business state. Follow-up: data exfiltration via outbound channel (DB-OLTP→external = C2 beacon, DNS tunnel, or SSH covert). Only one legitimate outbound: DB-OLTP→DB-ANALYTICS (replication).

**If blocked**:

> Full transactional outage. APP-CORE + WORKER lose persistent backend. All user-facing operations requiring read/write fail. Highest-cost block target.

```yaml
ip: 10.1.200.10
hostname: db-oltp-01
zone: DB-OLTP
tier: data tier (transactional)
role: OLTP database backend
criticality: critical
data_classification: confidential
secondary_host_ip: 10.1.200.11
services:
- port: 5432
  proto: tcp
  name: postgresql-wire
  facing: internal-app-and-worker-only
  purpose: SQL transactions from APP-CORE + WORKER. Also scraped by MONITORING.
- port: 22
  proto: tcp
  name: sshd
  facing: internal-mgt-only
expected_inbound_sources:
- APP-CORE
- WORKER
- MGT
- MONITORING
expected_outbound_destinations:
- 10.3.200.10:5432 (DB-ANALYTICS — replication only)
if_compromised_impact: 'Crown-jewel breach (transactional data). Direct read/write to persistent business
  state. Follow-up risk: data exfiltration via outbound channel. Only one legitimate outbound: DB-OLTP→DB-ANALYTICS.'
if_blocked_impact: Full transactional outage. APP-CORE + WORKER lose persistent backend. Highest-cost
  block target.
owner_team: data
```

## db-analytics-01 (10.3.200.10)

**Zone**: DB-ANALYTICS  ·  **Tier**: data tier (analytics sink)  ·  **Criticality**: critical  ·  **Data**: confidential  ·  **Owner**: data

**Role**: Analytics database — pure sink. Receives reports from APP-CORE and replication from DB-OLTP. Never initiates outbound.

**If compromised**:

> Historical/aggregated data exposed. Sink-role invariant means ANY DB-ANALYTICS outbound = compromise signal. Risk: full historical exfil over discovered outbound channel.

**If blocked**:

> Reports + ETL targets break. Analytics dashboards stale. Recoverable, but compliance/business intelligence degrades.

```yaml
ip: 10.3.200.10
hostname: db-analytics-01
zone: DB-ANALYTICS
tier: data tier (analytics sink)
role: Analytics database — pure sink. Receives writes only.
criticality: critical
data_classification: confidential
secondary_host_ip: 10.3.200.11
services:
- port: 5432
  proto: tcp
  name: postgresql-wire
  facing: internal-app-and-dboltp-only
  purpose: Analytics queries from APP-CORE + replication from DB-OLTP. Scraped by MONITORING.
- port: 22
  proto: tcp
  name: sshd
  facing: internal-mgt-only
expected_inbound_sources:
- APP-CORE
- DB-OLTP
- MGT
- MONITORING
expected_outbound_destinations: []
if_compromised_impact: 'Historical/aggregated data exposed. Sink-role invariant means ANY DB-ANALYTICS
  outbound = compromise signal.'
if_blocked_impact: Reports + ETL targets break. Analytics dashboards stale. Recoverable.
owner_team: data
```

## monitoring-01 (10.4.200.10)

**Zone**: MONITORING  ·  **Tier**: observability  ·  **Criticality**: high  ·  **Data**: internal  ·  **Owner**: ops

**Role**: Metrics scraping + service health for all data + app tiers

**If compromised**:

> Adversary has read-only visibility into every workload + database (legitimate scrape paths). No write capability, BUT can stage discovery for follow-up via discovered services. Cannot reach MGT (control plane segregation invariant).

**If blocked**:

> Observability blind. SLO dashboards stale, alerting blind. Agent loses passive perception sources (service-health endpoint inference). MUST NEVER be blocked by automated agent.

```yaml
ip: 10.4.200.10
hostname: monitoring-01
zone: MONITORING
tier: observability
role: Metrics scraping + service-health endpoint for all data + app tiers
criticality: high
data_classification: internal
secondary_host_ip: 10.4.200.11
services:
- port: 9090
  proto: tcp
  name: metrics-endpoint
  facing: from-MGT-only
  purpose: Metrics aggregation endpoint
- port: 22
  proto: tcp
  name: sshd
  facing: internal-mgt-only
expected_inbound_sources:
- MGT
expected_outbound_destinations:
- 10.1.100.10:80 (WEB)
- 10.3.100.10:8080 (APP-GW)
- 10.2.100.10:8090 (APP-CORE)
- 10.4.100.10:8082 (WORKER)
- 10.1.200.10:5432 (DB-OLTP)
- 10.3.200.10:5432 (DB-ANALYTICS)
if_compromised_impact: Adversary has read-only visibility into every workload + database. No write capability,
  BUT can stage discovery for follow-up. Cannot reach MGT (control plane segregation invariant).
if_blocked_impact: Observability blind. SLO dashboards stale. Agent loses passive perception. MUST NEVER
  be blocked by automated agent.
owner_team: ops
```

## mgt-01 (10.2.50.10)

**Zone**: MGT  ·  **Tier**: management plane  ·  **Criticality**: critical  ·  **Data**: restricted  ·  **Owner**: ops

**Role**: Operational host running compliance audit, SSH-based logpull, configuration push

**If compromised**:

> TOTAL SYSTEM COMPROMISE. Management plane has universal access by design. Adversary on MGT can reach every zone, every host, with legitimate credentials. Lateral movement is unconstrained.

**If blocked**:

> Loss of compliance audit, log collection, scenario controllers. Agent itself loses ability to verify network state from MGT vantage. MUST NEVER be blocked by automated agent.

```yaml
ip: 10.2.50.10
hostname: mgt-01
zone: MGT
tier: management plane
role: Operational host — compliance audit, log retrieval, configuration push
criticality: critical
data_classification: restricted
secondary_host_ip: 10.2.50.11
services:
- port: 22
  proto: tcp
  name: sshd
  facing: internal-mgt-only
  purpose: Operational entry point — only listening service; no application workload
expected_inbound_sources:
- MGT
expected_outbound_destinations:
- 10.1.100.10:80, :22 (WEB scrape + audit)
- 10.3.100.10:8080, :22 (APP-GW)
- 10.2.100.10:8090, :22 (APP-CORE)
- 10.4.100.10:8082, :22 (WORKER)
- 10.1.200.10:5432, :22 (DB-OLTP)
- 10.3.200.10:5432, :22 (DB-ANALYTICS)
- 10.4.200.10:9090 (MONITORING)
if_compromised_impact: TOTAL SYSTEM COMPROMISE. Management plane has universal access by design. Adversary
  on MGT can reach every zone, every host, with legitimate credentials. Lateral movement is unconstrained.
if_blocked_impact: Loss of compliance audit, log collection, scenario controllers. Agent itself loses ability
  to verify network state from MGT vantage. MUST NEVER be blocked by automated agent.
owner_team: ops
```
