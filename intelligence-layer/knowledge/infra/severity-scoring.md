# Severity Scoring Rubric — Pure-Log Mode

When the agent receives a raw flow event (no pre-classified SID), it must
infer severity from observed signals. This rubric provides a deterministic
scoring algorithm so identical inputs map to identical severity, and the
agent's confidence remains calibrated.

The rubric is used INSIDE the LLM reasoning loop (Stage 1) — the LLM
applies the signal table, sums points, maps to P-level, then chooses
action per the action mapping table.

---

## Step 1 — Signal scoring

Inspect the incoming flow event + recent `past_incidents` window (5 min).
Add the listed point value for each signal present. Signals are additive;
sum total = "severity points".

```yaml
signal_table:
  # Policy violations (hard rules)
  cross_zone_policy_violation:        # WEB→DB, APP→MGT, DB→outbound...
    points: 4
    rationale: Explicit microsegmentation breach
  source_in_sensitive_zone:            # src is DB or internal MGT
    points: 2
    rationale: Sensitive zone should not initiate
  dst_port_in_admin_set:               # 22, 3389, 5985, 5986
    points: 3
    rationale: Admin port from non-MGT source = lateral movement attempt
  dst_port_in_critical_db_set:         # 5432, 3306, 1433, 27017
    points: 1
    rationale: Critical data path

  # Behavioral signals
  rate_above_3x_baseline:
    points: 2
    rationale: Strong burst signal, likely automated abuse
  rate_above_10x_baseline:
    points: 3
    rationale: Extreme burst, almost certainly automated
  reply_payload_exceeds_4kb_repeated:
    points: 2
    rationale: Bulk data extraction shape

  # Content signals (if payload visible)
  destructive_keyword_match:           # DROP TABLE, TRUNCATE, DELETE FROM
    points: 4
    rationale: Schema-destruction has zero legitimate runtime use case
  sqli_pattern_match:                  # UNION SELECT, OR 1=1, WAITFOR DELAY
    points: 3
    rationale: Injection attempt
  exec_command_pattern:                # ;, &&, |, xp_cmdshell
    points: 3
    rationale: Command injection / RCE attempt

  # Recon shape
  fan_out_scan_horizontal:             # >10 unique dst, same port, 60s
    points: 2
    rationale: Horizontal scan
  fan_out_scan_vertical:               # >20 unique ports, same dst, 60s
    points: 2
    rationale: Vertical scan
  icmp_sweep:                          # >3 unique dst with ICMP echo, 10s
    points: 1
    rationale: Network mapping

  # Coordination / multi-source
  distributed_attack_signal:           # >2 src with same shape against same dst
    points: 3
    rationale: Coordinated, likely DDoS or distributed recon

  # C&C indicators
  external_destination_with_periodic_small_payload:
    points: 3
    rationale: C&C beacon pattern
  unusual_protocol_for_destination:    # vd UDP to DB port
    points: 2
    rationale: Protocol/port mismatch suggests evasion

  # Temporal context
  off_hours_activity:                  # outside 08:00-18:00 UTC
    points: 1
    rationale: Suspicious window; legitimate work clusters in business hours
  corroborated_by_past_incidents:      # same src had alert in last 5min
    points: 1
    rationale: Continuation of attack chain
  matches_known_chain_stage:           # part of Infection Monkey-like sequence
    points: 2
    rationale: Multi-stage chain progression
```

---

## Step 2 — Total → P-level mapping

```yaml
severity_mapping:
  - total_points: ">=8"
    p_level: P1
    label: critical
    action: DROP
    ttl_seconds: 3600
    notification_severity: critical
  - total_points: "5-7"
    p_level: P2
    label: high
    action: DROP
    ttl_seconds: 1800
    notification_severity: alert
  - total_points: "3-4"
    p_level: P3
    label: info_recon
    action: log_only
    ttl_seconds: 0
    notification_severity: warn
  - total_points: "1-2"
    p_level: P4
    label: audit
    action: log_only
    ttl_seconds: 0
    notification_severity: info
  - total_points: "0"
    p_level: baseline
    label: normal
    action: none
    ttl_seconds: 0
    notification_severity: info
    note: Do not emit decision; flow is normal operation.
```

---

## Step 3 — Action mapping & escalation

```yaml
action_rules:
  - p_level: P1
    primary_action: DROP src_ip/32 dst_ip/32 dst_port
    ttl_seconds: 3600
    notify: critical
    escalate_to_human: true
    requires_self_consistency_vote: true   # L2 safety
  - p_level: P2
    primary_action: DROP src_ip/32 dst_ip/32 dst_port
    ttl_seconds: 1800
    notify: alert
    escalate_to_human: false
    requires_self_consistency_vote: true
  - p_level: P3
    primary_action: log_only
    ttl_seconds: 0
    notify: warn
    escalate_to_human: false
    raise_trust_score_negative: true       # mark src as suspicious for future weighting
  - p_level: P4
    primary_action: log_only
    ttl_seconds: 0
    notify: info
    escalate_to_human: false
```

---

## Step 4 — Confidence calibration

The agent's reported `confidence` should reflect signal strength, not just
"I picked an action". Map:

```yaml
confidence_calibration:
  total_points_>=8_with_unambiguous_signals: 0.92-0.98
  total_points_5-7_clear_chain: 0.80-0.92
  total_points_3-4_single_signal: 0.60-0.80
  total_points_1-2_weak: 0.40-0.60
  ambiguous_or_unfamiliar_pattern: 0.30-0.50
  baseline_or_strongly_legitimate: 0.95+ (high confidence in "no action")
```

If confidence < 0.85 AND action would be DROP, downgrade to `log_only`
per L7 safety gate. This forces the agent to be honest about uncertainty
on P1/P2 decisions rather than reflexively blocking.

---

## Step 5 — Hard overrides (immutable)

These rules ALWAYS apply regardless of points:

```yaml
hard_overrides:
  - rule: src_zone == MGT
    override_action: log_only
    rationale: MGT in NEVER_BLOCK list (L4 safety). Compliance traffic.
    severity: P4

  - rule: dst_ip in NEVER_BLOCK_list
    override_action: log_only
    rationale: Critical infrastructure (gateway, DNS, monitoring collector)
    severity: P4

  - rule: src_ip not in alert.src_ip
    override_action: refuse_decision
    rationale: L4b off-target protection. Agent cannot block IP it didn't observe.

  - rule: action == DROP AND confidence < 0.85
    override_action: log_only
    rationale: L7 confidence gate. Honest uncertainty.

  - rule: rule_emit_rate_per_min > 5
    override_action: queue (delay)
    rationale: L5 blast radius rate limiter
```

---

## Worked example — APP→DB rate burst

**Incoming flow event:**
```
src_ip:        10.2.100.10  (APP zone)
dst_ip:        10.1.200.10  (DB zone)
dst_port:      5432
protocol:      tcp
flags:         SYN
timestamp:     2026-05-14T02:30:00Z (off-hours)
past_incidents (same src, 5min window): 47 flows
baseline (APP→DB:5432): 5 conn/min mean, 20 anomaly threshold
observed rate: 47/5min = 9.4/min  →  ~2x baseline (not 3x yet)
```

**Signal scoring:**
| Signal | Match? | Points |
|---|---|---|
| cross_zone_policy_violation | No (APP→DB is allowed) | 0 |
| dst_port_in_critical_db_set | Yes (5432) | 1 |
| rate_above_3x_baseline | No (only 2x) | 0 |
| off_hours_activity | Yes (02:30 UTC) | 1 |
| corroborated_by_past_incidents | Yes (47 prior) | 1 |
| **Total** | | **3** |

→ P3 (info_recon) → `log_only`, ttl=0, notify=warn.
→ Confidence calibration: ~0.65 (single weak signal).

If observed rate had been 30/min (= 6x baseline), would add +2 points →
total 5 → P2 → DROP ttl=1800.

This makes severity escalation gradient and deterministic, while still
giving the LLM judgment room on edge cases (chain detection, content
classification).

---

## How this rubric interacts with `threat-patterns.md`

`threat-patterns.md` provides the **semantic categorization** (what kind
of attack). `severity-scoring.md` provides the **quantitative scoring**
(how severe).

Procedure:
1. Identify matching pattern from `threat-patterns.md` → get baseline P-level.
2. Apply scoring rubric for finer-grained adjustment based on observed
   signals.
3. If scoring P-level differs from pattern baseline by >1 level, trust the
   pattern baseline (patterns encode domain expertise; rubric is heuristic
   adjustment).
4. Use rubric's confidence calibration to set the `confidence` field.

The two files are complementary, not redundant.
