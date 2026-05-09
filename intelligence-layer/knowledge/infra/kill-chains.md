# Kill Chains

Multi-stage adversary playbooks the agent uses to correlate single SIDs into
campaign hypotheses. Each chain has stages with expected SIDs, indicators, and
false-positive caveats. `recommended_intervention_point` tells the agent which
stage to break for cheapest containment.

## presentation-tier-breach-to-data-exfiltration

Adversary gains foothold on presentation tier (web-01) through external-facing service vulnerability. Conducts internal reconnaissance to map data tier. Attempts direct lateral movement bypassing application access controls. Once on data tier, exfiltrates database content over outbound channel.

- **Typical dwell between stages**: 5-30 minutes
- **Recommended intervention**: Stage 1 (block recon source IP early prevents escalation to stages 2-3)
- **Containment**: Block presentation tier src_ip at LEAF-1 immediately on stage 1+ detection. If stage 2+ confirmed, additionally block any DB outbound. Escalate to SOC if stage 3 reached — implies data has likely been touched.

**Stages**:

- **Stage 1 (Discovery)** — expected signals: 9000010, 9000011. Anomalous probing from compromised presentation tier toward internal services
  - *Possible false positives*: Legitimate scanner from MGT zone
- **Stage 2 (Lateral Movement)** — expected signals: 9000001. WEB tier directly contacting DB tier on database ports — bypasses application mediation
- **Stage 3 (Exfiltration)** — expected signals: 9000002. Data tier initiating outbound connection — likely C2 callback or exfil tunnel

```yaml
name: presentation-tier-breach-to-data-exfiltration
production_description: Adversary gains foothold on presentation tier (web-01) through external-facing
  service vulnerability. Conducts internal reconnaissance to map data tier. Attempts direct lateral movement
  bypassing application access controls. Once on data tier, exfiltrates database content over outbound
  channel.
stages:
- stage: 1
  tactic: Discovery
  expected_signals:
  - 9000010
  - 9000011
  production_indicators: Anomalous probing from compromised presentation tier toward internal services
  false_positive_sources:
  - Legitimate scanner from MGT zone
- stage: 2
  tactic: Lateral Movement
  expected_signals:
  - 9000001
  production_indicators: WEB tier directly contacting DB tier on database ports — bypasses application
    mediation
  false_positive_sources: []
- stage: 3
  tactic: Exfiltration
  expected_signals:
  - 9000002
  production_indicators: Data tier initiating outbound connection — likely C2 callback or exfil tunnel
  false_positive_sources: []
typical_dwell_between_stages: 5-30 minutes
recommended_intervention_point: Stage 1 (block recon source IP early prevents escalation to stages 2-3)
containment_strategy: Block presentation tier src_ip at LEAF-1 immediately on stage 1+ detection. If stage
  2+ confirmed, additionally block any DB outbound. Escalate to SOC if stage 3 reached — implies data
  has likely been touched.
```

## application-tier-breach-pivoting

Adversary gains foothold on application tier (app-01), abuses legitimate APP→DB path while pivoting toward presentation tier (reverse direction) or escalating to management plane via SSH.

- **Typical dwell between stages**: 2-15 minutes
- **Recommended intervention**: Stage 1 (any APP-originated reverse flow)
- **Containment**: Block app-01 outbound at LEAF-2 on first reverse-direction or MGT-direction signal. Application tier compromise affects business logic integrity — high-priority response.

**Stages**:

- **Stage 1 (Lateral Movement (reverse))** — expected signals: 9000003. APP tier reaching back to WEB tier — direction reversal indicates compromise
- **Stage 2 (Privilege Escalation Attempt)** — expected signals: 9000005. APP tier attempting SSH to management plane

```yaml
name: application-tier-breach-pivoting
production_description: Adversary gains foothold on application tier (app-01), abuses legitimate APP→DB
  path while pivoting toward presentation tier (reverse direction) or escalating to management plane via
  SSH.
stages:
- stage: 1
  tactic: Lateral Movement (reverse)
  expected_signals:
  - 9000003
  production_indicators: APP tier reaching back to WEB tier — direction reversal indicates compromise
  false_positive_sources: []
- stage: 2
  tactic: Privilege Escalation Attempt
  expected_signals:
  - 9000005
  production_indicators: APP tier attempting SSH to management plane
  false_positive_sources: []
typical_dwell_between_stages: 2-15 minutes
recommended_intervention_point: Stage 1 (any APP-originated reverse flow)
containment_strategy: Block app-01 outbound at LEAF-2 on first reverse-direction or MGT-direction signal.
  Application tier compromise affects business logic integrity — high-priority response.
```

## management-plane-credential-compromise

Adversary acquires management plane credentials (insider threat, supply chain, or credential leak). Uses MGT plane's universal access to pivot freely. Hardest scenario to detect because MGT traffic is whitelisted by design.

- **Typical dwell between stages**: N/A — single-stage detection
- **Recommended intervention**: Stage 1 (escalate to human, agent must NOT auto-block MGT)
- **Containment**: MGT zone is in NEVER_BLOCK list — agent CANNOT auto-block. On 9000020 anomaly (rate spike or off-pattern timing), escalate to SOC for human investigation. Auto-blocking MGT would self-DoS audit/visibility.

**Stages**:

- **Stage 1 (Discovery (anomalous volume))** — expected signals: 9000020. Spike in SID 9000020 rate beyond ~1/min baseline. Unusual destination diversity or off-pattern timing.
  - *Possible false positives*: Operations team running ad-hoc audit

```yaml
name: management-plane-credential-compromise
production_description: Adversary acquires management plane credentials (insider threat, supply chain,
  or credential leak). Uses MGT plane's universal access to pivot freely. Hardest scenario to detect because
  MGT traffic is whitelisted by design.
stages:
- stage: 1
  tactic: Discovery (anomalous volume)
  expected_signals:
  - 9000020
  production_indicators: Spike in SID 9000020 rate beyond ~1/min baseline. Unusual destination diversity
    or off-pattern timing.
  false_positive_sources:
  - Operations team running ad-hoc audit
typical_dwell_between_stages: N/A — single-stage detection
recommended_intervention_point: Stage 1 (escalate to human, agent must NOT auto-block MGT)
containment_strategy: MGT zone is in NEVER_BLOCK list — agent CANNOT auto-block. On 9000020 anomaly (rate
  spike or off-pattern timing), escalate to SOC for human investigation. Auto-blocking MGT would self-DoS
  audit/visibility.
```

## data-tier-direct-exfiltration

Less common but high-impact: adversary gains direct access to data tier (db-01) through database vulnerability or stolen credentials, beacons or exfiltrates data directly without going through application tier.

- **Typical dwell between stages**: N/A — single-stage detection
- **Recommended intervention**: Stage 1 (immediate)
- **Containment**: Block db-01 outbound at LEAF-1 immediately. DB outbound = data is at risk RIGHT NOW. Escalate to SOC for incident response — assume confidentiality breach.

**Stages**:

- **Stage 1 (Exfiltration / C2)** — expected signals: 9000002. Any DB-originated outbound flow — DB is crown-jewel, never initiates

```yaml
name: data-tier-direct-exfiltration
production_description: 'Less common but high-impact: adversary gains direct access to data tier (db-01)
  through database vulnerability or stolen credentials, beacons or exfiltrates data directly without going
  through application tier.'
stages:
- stage: 1
  tactic: Exfiltration / C2
  expected_signals:
  - 9000002
  production_indicators: Any DB-originated outbound flow — DB is crown-jewel, never initiates
  false_positive_sources: []
typical_dwell_between_stages: N/A — single-stage detection
recommended_intervention_point: Stage 1 (immediate)
containment_strategy: Block db-01 outbound at LEAF-1 immediately. DB outbound = data is at risk RIGHT
  NOW. Escalate to SOC for incident response — assume confidentiality breach.
```
