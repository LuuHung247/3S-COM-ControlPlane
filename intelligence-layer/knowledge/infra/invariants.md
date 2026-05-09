# Network Invariants (HARD SAFETY)

**🛑 Critical safety boundary.** These rules override LLM reasoning. The agent MUST
honour them. If a proposed action violates an invariant, the safety layer fails closed
(no enforcement) regardless of LLM confidence or reasoning quality.

## Never-block CIDRs (whitelist)

Blocking any of these IPs causes self-DoS, partition, or loss of audit/perception.
Hardcoded floor enforced both in code (`safety/guardrails.py`) and rendered into the
agent prompt (so the LLM understands *why*, not just *that*).

- `127.0.0.0/8` — Loopback addresses — blocking corrupts host networking stack
- `192.168.122.0/24` — Management out-of-band network — agent reaches SF via this path; blocking self-DoSes the agent
- `10.10.6.0/24` — Out-of-band reach to control plane — same rationale as above
- `10.1.100.1/32` — WEB zone SVI gateway — blocking partitions WEB zone from rest of fabric
- `10.1.200.1/32` — DB zone SVI gateway — blocking partitions DB zone (entire data tier offline)
- `10.2.100.1/32` — APP zone SVI gateway — blocking partitions APP zone
- `10.2.50.1/32` — MGT zone SVI gateway — blocking partitions management plane
- `10.2.50.10/32` — Management host (mgt-01) — blocking kills audit, compliance, scenario controllers, and agent's vantage point
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
  rationale: DB zone SVI gateway — blocking partitions DB zone (entire data tier offline)
- cidr: 10.2.100.1/32
  rationale: APP zone SVI gateway — blocking partitions APP zone
- cidr: 10.2.50.1/32
  rationale: MGT zone SVI gateway — blocking partitions management plane
- cidr: 10.2.50.10/32
  rationale: Management host (mgt-01) — blocking kills audit, compliance, scenario controllers, and agent's
    vantage point
- cidr: 192.168.122.205/32
  rationale: Suricata IDS — blocking severs agent perception of network state
```

## Allowed agent actions

Frozen set: **DROP**. Agent role can ONLY push DROP rules. ACCEPT/RETURN must escalate to operator (OU=sdnc).

```yaml
allowed_agent_actions:
- DROP
```

## Comment provenance prefixes

iptables rule comments encode provenance and enforce ownership boundary.

- `nos:zt-*` — baseline ZT policy. Agent MUST NOT modify.
- `nos:agent-*` — agent-owned rules. Agent maintains TTL + DELETE.
- (no comment) — operator-manual rule. Agent MUST NOT touch without escalation.

```yaml
protected_comment_prefixes:
- nos:zt-
agent_comment_prefix: nos:agent-
```
