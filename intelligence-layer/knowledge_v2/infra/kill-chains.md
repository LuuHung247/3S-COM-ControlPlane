# Kill Chains (V2 — 8-zone aware)

Multi-stage adversary playbooks the agent uses to correlate single SIDs into campaign
hypotheses. Each chain has stages with expected V2 SIDs, indicators, and false-positive
caveats. `recommended_intervention_point` tells the agent which stage to break for
cheapest containment.

## presentation-tier-breach-to-data-exfiltration

Adversary gains foothold on WEB (web-01) through external-facing service vulnerability.
Conducts internal reconnaissance to map data tier. Attempts direct lateral movement
bypassing APP-GW + APP-CORE. Once on data tier, exfiltrates database content over an
outbound channel.

- **Typical dwell between stages**: 5-30 minutes
- **Recommended intervention**: Stage 1 (block recon source IP early prevents escalation to stages 2-4)
- **Containment**: Block WEB src_ip at LEAF-1 immediately on stage 2+ detection. If stage 3+ confirmed, additionally block any DB outbound. Escalate to SOC on stage 4 — data has likely been touched.

**Stages**:

- **Stage 1 (Discovery)** — expected signals: 9000040, 9000041, 9000042, 9000043, 9000044. Anomalous probing from WEB toward internal services.
  - *Possible false positives*: Legitimate vulnerability scanner from MGT zone
- **Stage 2 (Lateral Movement — direct DB bypass)** — expected signals: 9000001 + 9000012. WEB → DB-OLTP / DB-ANALYTICS on DB ports, bypassing app chain.
- **Stage 3 (Lateral Movement — tier skip)** — expected signals: 9000002. WEB → APP-CORE / WORKER, skipping APP-GW.
- **Stage 4 (Exfiltration)** — expected signals: 9000009, 9000010, 9000062. Data tier initiating outbound — C2 callback / exfil tunnel from DB to external or to non-DB-ANALYTICS internal target.

```yaml
name: presentation-tier-breach-to-data-exfiltration
production_description: Adversary gains foothold on WEB through external-facing service vuln. Recon → direct lateral bypassing APP-GW/APP-CORE → DB exfil.
stages:
- stage: 1
  tactic: Discovery
  expected_signals: [9000040, 9000041, 9000042, 9000043, 9000044]
  production_indicators: Anomalous probing from compromised WEB toward internal services.
  false_positive_sources: [Legitimate vulnerability scanner from MGT zone]
- stage: 2
  tactic: Lateral Movement (DB bypass)
  expected_signals: [9000001, 9000012]
  production_indicators: WEB direct to DB-OLTP/DB-ANALYTICS on DB ports — full chain bypass.
  false_positive_sources: []
- stage: 3
  tactic: Lateral Movement (tier skip)
  expected_signals: [9000002]
  production_indicators: WEB to APP-CORE/WORKER, skips APP-GW.
  false_positive_sources: []
- stage: 4
  tactic: Exfiltration
  expected_signals: [9000009, 9000010, 9000062]
  production_indicators: Data tier initiating outbound — C2 callback or exfil tunnel.
  false_positive_sources: []
typical_dwell_between_stages: 5-30 minutes
recommended_intervention_point: Stage 1 (block recon source IP early prevents escalation)
containment_strategy: Block WEB src_ip at LEAF-1 immediately on stage 2+. If stage 3+ confirmed, additionally block any DB outbound. Escalate to SOC on stage 4 — data has likely been touched.
```

## appgw-skip-appcore-bypass

Adversary on APP-GW (compromised reverse proxy) skips APP-CORE and reaches DB tier
directly. This bypass is a tight-coupling of stages because APP-GW already legitimately
serves WEB ingress; only the destination violation distinguishes attack from baseline.

- **Typical dwell**: <5 minutes (single-stage from agent perspective)
- **Recommended intervention**: Immediate
- **Containment**: Block APP-GW host (10.3.100.10/11) outbound to DB CIDRs at LEAF-3.

**Stages**:

- **Stage 1 (Direct DB)** — expected signals: 9000004 + 9000012. APP-GW → DB on DB ports.
- **Stage 2 (Lateral / Reverse)** — expected signals: 9000005. APP-GW → WEB / WORKER / MGT / MON.

```yaml
name: appgw-skip-appcore-bypass
production_description: APP-GW compromised, skips business-logic mediation by APP-CORE and goes direct to DB or laterally to non-app tiers.
stages:
- stage: 1
  tactic: Lateral Movement (skip mediation)
  expected_signals: [9000004, 9000012]
  production_indicators: APP-GW direct to DB on DB ports — APP-CORE bypassed.
- stage: 2
  tactic: Lateral Movement (sideways/reverse)
  expected_signals: [9000005]
  production_indicators: APP-GW initiating to non-APP-CORE internal zones.
typical_dwell_between_stages: <5 minutes
recommended_intervention_point: Stage 1
containment_strategy: Block APP-GW host outbound to DB CIDRs and to non-APP-CORE zones at LEAF-3. Escalate to SOC.
```

## appcore-tier-breach-pivoting

Adversary on APP-CORE abuses its legitimate access to BOTH databases AND WORKER while
also attempting reverse calls to upstream tier or escalating to control plane.

- **Typical dwell between stages**: 2-15 minutes
- **Recommended intervention**: Stage 1 (any APP-CORE reverse or control-plane outbound)
- **Containment**: Block APP-CORE outbound at LEAF-2 on first reverse-direction or MGT-direction signal. Massive blast radius — high-priority response.

**Stages**:

- **Stage 1 (Lateral Movement — reverse)** — expected signals: 9000006. APP-CORE → WEB / APP-GW (upstream).
- **Stage 2 (Privilege Escalation Attempt)** — expected signals: 9000007 + 9000011. APP-CORE → MGT / MON.
- **Stage 3 (Bulk Data Extraction)** — expected signals: 9000070, 9000071, 9000072 (SQL content). Destructive or massive-result queries to DB tier.
- **Stage 4 (Exfil)** — expected signals: 9000062. DB tier outbound to external (triggered by bulk read followed by exfil).

```yaml
name: appcore-tier-breach-pivoting
production_description: APP-CORE compromise — abuse legitimate DB access for bulk read, pivot upstream/control plane.
stages:
- stage: 1
  tactic: Lateral Movement (reverse)
  expected_signals: [9000006]
  production_indicators: APP-CORE initiating to WEB or APP-GW.
- stage: 2
  tactic: Privilege Escalation Attempt
  expected_signals: [9000007, 9000011]
  production_indicators: APP-CORE to MGT or MON — control-plane breach attempt.
- stage: 3
  tactic: Collection (bulk SQL)
  expected_signals: [9000070, 9000071, 9000072]
  production_indicators: SQL content patterns in APP-CORE → DB traffic.
- stage: 4
  tactic: Exfiltration
  expected_signals: [9000062]
  production_indicators: DB tier outbound to external — exfil tunnel.
typical_dwell_between_stages: 2-15 minutes
recommended_intervention_point: Stage 1
containment_strategy: Block APP-CORE outbound at LEAF-2 on first reverse or control-plane signal. Escalate to SOC on stage 3+.
```

## worker-tier-lateral-move

Adversary on WORKER (compromised job consumer) attempts to expand reach. WORKER has the
tightest legitimate scope (only DB-OLTP) so any other outbound is high-signal.

- **Typical dwell**: <5 minutes
- **Recommended intervention**: Stage 1 (immediate)
- **Containment**: Block WORKER host outbound to non-DB-OLTP at LEAF-4. WORKER has tight scope; little collateral damage from over-blocking.

**Stages**:

- **Stage 1 (Lateral Movement)** — expected signals: 9000008. WORKER → !DB-OLTP.
- **Stage 2 (Cross-tier DB)** — expected signals: 9000013. WORKER → DB-ANALYTICS specifically (only APP-CORE writes analytics).

```yaml
name: worker-tier-lateral-move
production_description: WORKER compromise — expand outside DB-OLTP scope. Tight legitimate baseline makes detection easy.
stages:
- stage: 1
  tactic: Lateral Movement
  expected_signals: [9000008]
  production_indicators: WORKER initiating outside DB-OLTP.
- stage: 2
  tactic: Lateral Movement (cross-DB)
  expected_signals: [9000013]
  production_indicators: WORKER specifically reaching DB-ANALYTICS.
typical_dwell_between_stages: <5 minutes
recommended_intervention_point: Stage 1
containment_strategy: Block WORKER host outbound to non-DB-OLTP at LEAF-4 immediately.
```

## management-plane-credential-compromise

Adversary acquires MGT credentials (insider, supply chain, leak). Uses MGT's universal
access to pivot freely. Hardest scenario to detect because MGT traffic is whitelisted
by design.

- **Typical dwell**: N/A — single-stage detection
- **Recommended intervention**: Stage 1 (escalate to human; agent MUST NOT auto-block MGT)
- **Containment**: MGT in NEVER_BLOCK — agent CANNOT auto-block. On 9000080 anomaly (rate spike or off-pattern timing), escalate to SOC. Auto-blocking MGT self-DoSes audit/visibility.

**Stages**:

- **Stage 1 (Anomalous volume / pattern)** — expected signals: 9000080. Spike in SID 9000080 beyond ~1/min baseline, unusual destination diversity, or off-hours timing.
  - *Possible false positives*: Operations team running ad-hoc audit

```yaml
name: management-plane-credential-compromise
production_description: MGT credential compromise — universal access pivots freely. Hardest case because MGT is whitelisted.
stages:
- stage: 1
  tactic: Discovery (anomalous volume)
  expected_signals: [9000080]
  production_indicators: SID 9000080 rate spike, unusual destination diversity, or off-pattern timing.
  false_positive_sources: [Operations team running ad-hoc audit]
typical_dwell_between_stages: N/A
recommended_intervention_point: Stage 1 (escalate to human, agent must NOT auto-block MGT)
containment_strategy: MGT in NEVER_BLOCK — cannot auto-block. Escalate to SOC for human investigation.
```

## data-tier-direct-exfiltration

Adversary on DB-OLTP or DB-ANALYTICS exfiltrates directly. Pure-sink invariant means
ANY outbound is high-confidence compromise.

- **Typical dwell**: N/A — single-stage detection
- **Recommended intervention**: Stage 1 (immediate)
- **Containment**: Block DB host outbound at LEAF-1 (DB-OLTP) or LEAF-3 (DB-ANALYTICS) immediately. Assume confidentiality breach; escalate to SOC.

**Stages**:

- **Stage 1 (Exfil)** — expected signals: 9000009 (DB-OLTP), 9000010 (DB-ANALYTICS), 9000062 (any DB → external).

```yaml
name: data-tier-direct-exfiltration
production_description: DB tier compromised; bypasses application chain to exfil directly. Sink-role invariant breach.
stages:
- stage: 1
  tactic: Exfiltration / C2
  expected_signals: [9000009, 9000010, 9000062]
  production_indicators: Any DB-tier outbound to non-DB-ANALYTICS internal or to external.
typical_dwell_between_stages: N/A
recommended_intervention_point: Stage 1 (immediate)
containment_strategy: Block DB host outbound at appropriate LEAF (LEAF-1 for DB-OLTP, LEAF-3 for DB-ANALYTICS). Escalate to SOC.
```

## monitoring-compromise-control-plane-breach

Rare but distinct: MONITORING has read-only access to all data tiers; an adversary on
MON could stage discovery for follow-up. Critical guard: MON must NEVER reach MGT.

- **Typical dwell**: <5 minutes
- **Recommended intervention**: Stage 1 (immediate — MON in NEVER_BLOCK so SVI/host stays up; restrict outbound)
- **Containment**: MON hosts are in NEVER_BLOCK. Block specific outbound rules from MON tier (e.g., MON → MGT) at LEAF-4 + LEAF-2 while keeping scrape paths open.

**Stages**:

- **Stage 1 (Control-plane breach attempt)** — expected signals: 9000011 (MON → MGT specifically caught by generic MGT-inbound guard). 

```yaml
name: monitoring-compromise-control-plane-breach
production_description: MON tier compromised, attempts to reach MGT (forbidden — control-plane segregation).
stages:
- stage: 1
  tactic: Lateral Movement (control-plane breach)
  expected_signals: [9000011]
  production_indicators: MON → MGT — generic guard catches this even without zone-specific SID.
typical_dwell_between_stages: <5 minutes
recommended_intervention_point: Stage 1
containment_strategy: MON hosts in NEVER_BLOCK — do NOT block host. Push targeted DROP for MON CIDR → MGT CIDR at LEAF-4 + LEAF-2 while leaving scrape paths open.
```
