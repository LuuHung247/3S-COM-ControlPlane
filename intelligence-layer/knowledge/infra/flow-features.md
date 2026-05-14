# Flow Feature Extraction — Pure-Log Mode

When the agent receives a raw flow event (from `eve.json type:flow`), it
should reason in terms of the same **feature set** that NetVigil (NSDI'24)
extracts from NSG flow logs. Aggregation level = **IP-pair** (not 5-tuple),
which reduces graph size 100× and enables port-scan / fan-out detection.

This file specifies (1) the feature set the agent extracts per IP pair,
(2) aggregation window choice, (3) "unseen port" tracking, and
(4) how features map to threat patterns.

---

## Feature set per IP-pair (window = 2 min)

Each `(src_ip, dst_ip)` pair within a 2-minute window has the following
9 features. Per NetVigil Table 2 (NSDI'24).

```yaml
features_per_ip_pair:
  # Volume statistics (5 sub-stats each: min/max/mean/sum/std)
  - name: tx_packets
    sub_stats: [min, max, mean, sum, std]
    description: Packets sent from src to dst
  - name: rx_packets
    sub_stats: [min, max, mean, sum, std]
    description: Packets sent from dst to src
  - name: tx_bytes
    sub_stats: [min, max, mean, sum, std]
    description: Bytes sent from src to dst
  - name: rx_bytes
    sub_stats: [min, max, mean, sum, std]
    description: Bytes sent from dst to src

  # Flow counts (per protocol)
  - name: tcp_flow_count
    description: Number of TCP flows between this IP pair in window
  - name: udp_flow_count
    description: Number of UDP flows between this IP pair in window

  # Port-level features (key for scan detection)
  - name: unique_dst_ports
    description: Number of distinct dst ports observed for this src→dst pair
  - name: local_unseen_ports
    description: |
      Number of dst ports never seen for this IP pair in baseline training data.
      Strong scan indicator — legitimate flows reuse small port set.
  - name: global_unseen_ports
    description: |
      Number of dst ports never seen ANYWHERE in baseline. New service exposure.
```

---

## Window choice

```yaml
detection_window:
  default_seconds: 120        # 2-minute (matches NetVigil)
  rationale: |
    Balance between detection latency (lower = faster MTTD) and statistical
    power (higher = more samples per pair, less noise).
  alternatives:
    - 30s: low MTTD, noisy (single connection looks anomalous)
    - 60s: middle ground
    - 300s: more stable, but 5-min MTTD inferior to ~2-min
```

---

## "Unseen port" tracking — the secret sauce

NetVigil emphasizes "unseen ports" as a strong indicator of:
- **Port scan** — many unseen ports for the scanning src
- **Lateral movement** — attacker probes service it hasn't accessed before
- **Service exposure attempt** — workload tries new outbound port

```yaml
unseen_port_baseline:
  source: "Tracked from prior weeks of clean traffic"
  storage: Redis or Postgres lookup table per (src_ip, dst_ip)
  refresh: Continuous learning — exclude windows flagged anomalous from baseline update

policy:
  - rule: unique_dst_ports > 10 AND local_unseen_ports > 5 in 60s
    likely_pattern: vertical_port_scan
    severity_signal_points: 2
  - rule: dst_ip varies > 10 AND same dst_port AND any flow with local_unseen_port
    likely_pattern: horizontal_fanout_scan
    severity_signal_points: 2
```

---

## Why IP-pair aggregation (not flow-level)

```yaml
aggregation_tradeoff:
  flow_level_per_5_tuple:
    pros: [granular, exact match per session]
    cons: [graph size huge — production trace 139k nodes / 115k edges]
  ip_pair_aggregation:
    pros: [tractable — 300 nodes / 10-20k edges in same trace,
           captures port-fan-out, simpler LLM context]
    cons: [loses per-session detail — irrelevant for east-west anomaly]
```

→ Agent reasons at IP-pair level. If a specific session needs deep dive
(e.g., DPI flag for destructive SQL content), the agent fetches the
specific eve.json line via `flow_id` from the IP-pair record.

---

## Mapping features → threat-patterns.md signatures

Direct mapping how each feature contributes to which pattern:

```yaml
feature_to_pattern_map:
  tx_packets.sum:
    high → [syn_flood_dos, rate_burst_anomaly, c2_beacon (low-volume periodic)]
    low_periodic → [c2_beacon]
  rx_bytes.max:
    very_high → [volume_exfiltration_outbound, dns_amplification]
  tcp_flow_count + udp_flow_count:
    high_imbalance → protocol_anomaly
  unique_dst_ports:
    high (>20 in 60s) → vertical_port_scan
  local_unseen_ports:
    high → [lateral_movement_chain, port_scan, service_discovery]
  global_unseen_ports:
    high → [novel attack signature, zero-day]
```

---

## Agent reasoning procedure

When agent receives a raw flow event, recommended sequence:

1. **Aggregate** — group event into current 2-min window by `(src_ip, dst_ip)`.
2. **Compute features** — fill the 9 features above for this IP pair.
3. **Compare against baseline** — fetch `flow_baselines` from `baselines.md`
   for matching `(src_zone, dst_zone, dst_port)`.
4. **Match threat-patterns.md** — find pattern whose `flow_signature` aligns
   with observed features.
5. **Score severity** — apply `severity-scoring.md` point table.
6. **Decide action** — output `POLICY_DECISION_SCHEMA`.

If feature set or pattern matches multiple candidates, pick highest severity
(fail-safe) and lower confidence to reflect ambiguity.

---

## Note on content inspection

NetVigil flow-only approach cannot detect content-based attacks (SQL injection,
destructive SQL). Per paper Table 4, NetVigil AUC for SQL injection is 0.64
(weakest result). The lab's `eve.json` includes `http` and `dns` event types
in addition to `flow` — agent can use these for content classification when
needed, complementing flow-level reasoning. See `threat-patterns.md` Class F
(content_attack patterns).
