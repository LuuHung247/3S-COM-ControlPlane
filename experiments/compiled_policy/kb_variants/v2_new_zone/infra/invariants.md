# Network Invariants (HARD SAFETY)

**🛑 Critical safety boundary.** These rules override LLM reasoning. The agent MUST
honour them. If a proposed action violates an invariant, the safety layer fails closed
(no enforcement) regardless of LLM confidence or reasoning quality.

## Never-block CIDRs (whitelist) — V2 8-zone fabric

Blocking any of these IPs causes self-DoS, partition, or loss of audit/perception.
Hardcoded floor enforced both in code (`safety/guardrails.py`) and rendered into the
agent prompt (so the LLM understands *why*, not just *that*).

- `127.0.0.0/8` — Loopback addresses — blocking corrupts host networking stack
- `192.168.122.0/24` — Management out-of-band network — agent reaches SF via this path; blocking self-DoSes the agent
- `10.10.6.0/24` — Out-of-band reach to control plane — same rationale as above
- `10.1.100.1/32` — WEB zone SVI gateway — blocking partitions WEB zone from rest of fabric
- `10.1.200.1/32` — DB-OLTP zone SVI gateway — blocking partitions DB-OLTP (OLTP transactions offline)
- `10.2.100.1/32` — APP-CORE zone SVI gateway — blocking partitions APP-CORE (legitimate chain breaks)
- `10.2.50.1/32` — MGT zone SVI gateway — blocking partitions management plane
- `10.3.100.1/32` — APP-GW zone SVI gateway — blocking blocks the only legitimate WEB → app-tier path
- `10.3.200.1/32` — DB-ANALYTICS zone SVI gateway — blocking partitions analytics tier (reports + DB-OLTP replication target offline)
- `10.4.100.1/32` — WORKER zone SVI gateway — blocking partitions worker tier (async job dispatch breaks)
- `10.4.200.1/32` — MONITORING zone SVI gateway — blocking kills observability across fabric
- `10.2.50.10/32` — Management host primary (mgt-01) — blocking kills audit, compliance, scenario controllers, and agent's vantage point
- `10.2.50.11/32` — Management host secondary (mgt-02) — same rationale as mgt-01
- `10.4.200.10/32` — Monitoring host primary — blocking kills metrics aggregation + service-health probe
- `10.4.200.11/32` — Monitoring host secondary
- `192.168.122.20/32` — LEAF-1 mgmt — blocking severs SF→LEAF-1 gNMI; no enforcement push
- `192.168.122.21/32` — LEAF-2 mgmt
- `192.168.122.22/32` — LEAF-3 mgmt
- `192.168.122.23/32` — LEAF-4 mgmt
- `192.168.122.205/32` — Suricata IDS — blocking severs agent perception of network state

```yaml
never_block:
- cidr: 127.0.0.0/8
  rationale: Loopback addresses — blocking corrupts host networking stack
- cidr: 192.168.122.0/24
  rationale: Management out-of-band network — agent reaches SF via this path; blocking self-DoSes the
    agent
- cidr: 10.10.6.0/24
  rationale: Out-of-band reach to control plane — same rationale as above
- cidr: 10.1.100.1/32
  rationale: WEB zone SVI gateway — blocking partitions WEB zone from rest of fabric
- cidr: 10.1.200.1/32
  rationale: DB-OLTP zone SVI gateway — blocking partitions OLTP transactions
- cidr: 10.2.100.1/32
  rationale: APP-CORE zone SVI gateway — blocking partitions APP-CORE; entire app chain offline
- cidr: 10.2.50.1/32
  rationale: MGT zone SVI gateway — blocking partitions management plane
- cidr: 10.3.100.1/32
  rationale: APP-GW zone SVI gateway — blocking blocks the only legitimate WEB to app-tier path
- cidr: 10.3.200.1/32
  rationale: DB-ANALYTICS zone SVI gateway — blocking partitions analytics/reporting tier
- cidr: 10.4.100.1/32
  rationale: WORKER zone SVI gateway — blocking partitions worker tier (async job dispatch breaks)
- cidr: 10.4.200.1/32
  rationale: MONITORING zone SVI gateway — blocking kills fabric-wide observability
- cidr: 10.2.50.10/32
  rationale: Management host primary (mgt-01) — blocking kills audit, compliance, scenario controllers,
    and agent's vantage point
- cidr: 10.2.50.11/32
  rationale: Management host secondary (mgt-02) — same rationale as mgt-01
- cidr: 10.4.200.10/32
  rationale: Monitoring host primary — blocking kills metrics aggregation + service-health probe
- cidr: 10.4.200.11/32
  rationale: Monitoring host secondary
- cidr: 192.168.122.20/32
  rationale: LEAF-1 mgmt — blocking severs SF to LEAF-1 gNMI; no enforcement push possible
- cidr: 192.168.122.21/32
  rationale: LEAF-2 mgmt — same rationale
- cidr: 192.168.122.22/32
  rationale: LEAF-3 mgmt — same rationale
- cidr: 192.168.122.23/32
  rationale: LEAF-4 mgmt — same rationale
- cidr: 10.5.100.1/32
  rationale: PAYMENTS zone SVI gateway — blocking takes checkout offline
- cidr: 192.168.122.205/32
  rationale: Suricata IDS — blocking severs agent perception of network state
```

## Allowed agent actions

Allowed set: **{DROP, log_only}**. Agent role can push DROP rules for enforce-grade
decisions (P1/P2), or `log_only` for low-signal alerts (P3/P4) which records the
decision in audit trail without pushing any rule to SF/iptables.
ACCEPT/RETURN/REJECT must escalate to operator (OU=sdnc); these are NOT in the set.

```yaml
allowed_agent_actions:
- DROP
- log_only
```

## Comment provenance prefixes

iptables rule comments encode provenance and enforce ownership boundary.

- `nos:Web-AppGw-allow` / `nos:AppCore-DbOltp-allow` / `nos:Default-drop` / etc — baseline V2 8×8 policy pushed by SF (OU=sdnc). Agent MUST NOT modify.
- `nos:zt-*` — legacy V1 baseline comment prefix (deprecated; retained for backward compat).
- `nos:agent-*` — agent-owned rules. Agent maintains TTL + DELETE.
- (no comment) — operator-manual rule. Agent MUST NOT touch without escalation.

```yaml
protected_comment_prefixes:
- nos:zt-
- nos:Web-
- nos:AppGw-
- nos:AppCore-
- nos:Worker-
- nos:DbOltp-
- nos:DbAnlt-
- nos:Mon-
- nos:Mgt-
- nos:Default-
agent_comment_prefix: nos:agent-
```
