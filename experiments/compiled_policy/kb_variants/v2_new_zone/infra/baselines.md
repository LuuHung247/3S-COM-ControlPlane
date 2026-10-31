# Production Traffic Baselines (V2 — 8 zones / 16 hosts)

Steady-state east-west volume: **~250-500 flows/minute**. P4 audit emissions (SID 9000080
MGT, SID 9000081 MON) are REQUIRED VISIBILITY by compliance design — they are NOT
incidents. Anything matching a baseline is normal operation. Anything outside this set
is either new application behaviour or intrusion.

## Constants

```yaml
steady_state_flows_per_minute_min: 250
steady_state_flows_per_minute_max: 500
mgt_audit_alert_rate_per_minute: 1     # SID 9000080 threshold:limit 1/60s
mon_audit_alert_rate_per_5min: 1       # SID 9000081 threshold:limit 1/300s
business_hours_utc: "08:00-18:00"
off_hours_utc: "18:00-08:00"
```

## Statistical bounds per flow type (used by pure-log severity scoring)

Each canonical east-west flow has explicit mean / p95 / anomaly threshold. The agent
compares observed rate against these bounds to compute `rate_above_3x_baseline` and
`rate_above_10x_baseline` signals (see `severity-scoring.md`).

```yaml
flow_baselines:
  WEB_to_APPGW_8080:
    src_zone: WEB
    dst_zone: APP-GW
    dst_port: 8080
    cadence_seconds: 30
    mean_rate_per_minute_business_hours: 60
    mean_rate_per_minute_off_hours: 10
    p95_rate_per_minute: 120
    anomaly_threshold_3x: 180
    anomaly_threshold_10x: 600
    typical_dsize_bytes: 800
    time_distribution: business_hours_peaked

  APPGW_to_APPCORE_8090:
    src_zone: APP-GW
    dst_zone: APP-CORE
    dst_port: 8090
    cadence_seconds: 30
    mean_rate_per_minute_business_hours: 60
    mean_rate_per_minute_off_hours: 10
    p95_rate_per_minute: 120
    anomaly_threshold_3x: 180
    anomaly_threshold_10x: 600

  APPCORE_to_DBOLTP_5432:
    src_zone: APP-CORE
    dst_zone: DB-OLTP
    dst_port: 5432
    cadence_seconds: 30
    mean_rate_per_minute_business_hours: 60
    mean_rate_per_minute_off_hours: 5
    p95_rate_per_minute: 100
    anomaly_threshold_3x: 180
    anomaly_threshold_10x: 600
    typical_dsize_bytes_request: 200
    typical_dsize_bytes_reply: 100
    reply_payload_anomaly_threshold_bytes: 4096
    time_distribution: business_hours_peaked

  APPCORE_to_DBANLT_5432:
    src_zone: APP-CORE
    dst_zone: DB-ANALYTICS
    dst_port: 5432
    cadence_seconds: 60
    mean_rate_per_minute_business_hours: 30
    p95_rate_per_minute: 60
    anomaly_threshold_3x: 90
    anomaly_threshold_10x: 300

  APPCORE_to_WORKER_8082:
    src_zone: APP-CORE
    dst_zone: WORKER
    dst_port: 8082
    cadence_seconds: 45
    mean_rate_per_minute: 30
    p95_rate_per_minute: 60
    anomaly_threshold_3x: 90

  WORKER_to_DBOLTP_5432:
    src_zone: WORKER
    dst_zone: DB-OLTP
    dst_port: 5432
    cadence_seconds: 45
    mean_rate_per_minute: 30
    p95_rate_per_minute: 60
    anomaly_threshold_3x: 90

  DBOLTP_to_DBANLT_5432:
    src_zone: DB-OLTP
    dst_zone: DB-ANALYTICS
    dst_port: 5432
    cadence_seconds: 120
    mean_rate_per_minute: 10
    p95_rate_per_minute: 30
    anomaly_threshold_3x: 60
    note: ETL/replication only — sole legitimate DB-OLTP outbound

  MON_scrape_endpoints:
    src_zone: MONITORING
    dst_zones: [WEB, APP-GW, APP-CORE, WORKER, DB-OLTP, DB-ANALYTICS]
    cadence_seconds: 60
    mean_rate_per_minute_per_dst: 5
    p95_rate_per_minute_per_dst: 15
    note: 6 destinations × ~5/min = ~30/min total MON outbound

  MGT_ssh_audit:
    src_zone: MGT
    dst_zones: [WEB, APP-GW, APP-CORE, WORKER]
    dst_port: 22
    cadence_seconds: 120
    mean_rate_per_minute: 0.5
    p95_rate_per_minute: 5
    anomaly_threshold_3x: 15
    note: MGT in NEVER_BLOCK — high rate triggers alert but NEVER DROP

  external_outbound_workload:
    src_zones: [WEB, APP-GW, APP-CORE, WORKER, DB-OLTP, DB-ANALYTICS, MONITORING]
    dst: EXTERNAL_NET
    mean_rate_per_minute: 0
    anomaly_threshold_for_any: 1
    note: |
      Workload hosts must not initiate to external. DB tier never (sink). 
      DB-tier external initiation = SID 9000062 P1 exfil signal.
      WEB/APP-GW/APP-CORE/WORKER also never legitimately reach external in this lab.
```

## Time-of-day variation

Legitimate user-driven traffic clusters during business hours. The agent adjusts
severity based on observation timestamp.

```yaml
time_of_day_multipliers:
  business_hours_08_18_utc:
    severity_multiplier: 1.0
    legitimate_burst_likelihood: medium
  off_hours_22_06_utc:
    severity_multiplier: 1.5
    legitimate_burst_likelihood: low
  weekend:
    severity_multiplier: 1.3
    legitimate_burst_likelihood: low (except scheduled maintenance windows)
```

## Anomalous patterns (NOT in baseline — red flags)

Two classes of anomalies the agent must reason about:

**Class A — DENY-path violations** (LEAF already drops, but Suricata still alerts for audit):
- Any flow from DB-OLTP → non-DB-ANALYTICS — sink-near-role broken (9000009)
- Any flow from DB-ANALYTICS — pure-sink role broken (9000010)
- WEB initiating to DB-OLTP/DB-ANLT on any port — bypass full chain (9000001)
- WEB → APP-CORE / WORKER direct — skip APP-GW (9000002)
- WEB / APP-GW / APP-CORE / WORKER → MGT/MON — control-plane breach (9000003/5/7/8/11)
- Workload-to-workload SSH (non-MGT → port 22) — only MGT may SSH into workloads

**Class B — ALLOW-path abuse** (LEAF accepts; agent must detect — primary value-add):
- WEB→APP-GW connection rate above 180/min/src — baseline ~60/min; sustained burst suggests compromised web-tier weaponizing proxy
- APP-CORE→DB-OLTP connection rate above 180/min/src — baseline ~60/min; suggests compromised app abusing DB grant for bulk extraction
- DB-OLTP→APP-CORE (allowed-reverse via conntrack) reply payload exceeding 4KB repeated — bulk SELECT/JOIN extraction
- Destructive SQL fragments (DROP TABLE / TRUNCATE / DELETE FROM) in APP-CORE→DB-OLTP/DB-ANLT — SID 9000072
- WORKER→DB-OLTP rate above 90/min — baseline ~30/min; queue-flood or persist-loop abuse
- MON→DB-OLTP request payload >200B — MON scrape should be small probes; large payloads = MON compromise reading DB
- APP-CORE→DB activity in off-hours window — legitimate clusters during day; off-hours warrants extra scrutiny especially paired with rate/volume anomaly

```yaml
anomalous_patterns:
- Any flow originating from DB-OLTP to non-DB-ANALYTICS — sink-near-role broken (SID 9000009).
- Any flow originating from DB-ANALYTICS — pure-sink role broken (SID 9000010).
- WEB initiating to DB-OLTP/DB-ANALYTICS on any port — bypass full chain (SID 9000001).
- WEB to APP-CORE/WORKER direct — skip APP-GW (SID 9000002).
- WEB/APP-GW/APP-CORE/WORKER to MGT/MON — control-plane breach (SID 9000003/5/7/8/11).
- Workload-to-workload SSH (non-MGT to port 22) — only MGT may SSH into workloads.
- WEB->APP-GW connection rate above 180/min/src — baseline ~60/min.
- APP-CORE->DB-OLTP connection rate above 180/min/src — baseline ~60/min.
- DB-OLTP->APP-CORE reply payload exceeding 4KB repeated in short window.
- Destructive SQL fragments (DROP TABLE / TRUNCATE / DELETE FROM) in APP-CORE->DB traffic — SID 9000072.
- WORKER->DB-OLTP rate above 90/min — baseline ~30/min; queue-flood.
- MON->DB scrape request payload exceeding 200B — MON compromise reading DB.
- APP-CORE->DB activity in off-hours window — extra scrutiny especially with corroborating signal.
```

## Application traffic flows

### web-to-appgw-proxy

`10.1.100.10` → `10.3.100.10:8080/tcp`, cadence: every 30s, criticality: **critical**

Presentation tier proxies user HTTP requests to APP-GW for forwarding into the app chain.
Canonical user-request east-west entry into the chain.

```yaml
name: web-to-appgw-proxy
src_zone: WEB
src_ip: 10.1.100.10
dst_zone: APP-GW
dst_ip: 10.3.100.10
dst_port: 8080
proto: tcp
cadence: every 30s
expected_volume_per_hour: 120
burst_anomaly_threshold: '>180/min sustained suggests proxy abuse or DoS'
production_description: Presentation tier proxies user HTTP requests to the APP-GW (only legitimate WEB outbound).
criticality_to_business: critical
if_disrupted: End-user-facing path broken. Users cannot enter the app chain.
```

### appgw-to-appcore

`10.3.100.10` → `10.2.100.10:8090/tcp`, cadence: every 30s, criticality: **critical**

```yaml
name: appgw-to-appcore
src_zone: APP-GW
src_ip: 10.3.100.10
dst_zone: APP-CORE
dst_ip: 10.2.100.10
dst_port: 8090
proto: tcp
cadence: every 30s
expected_volume_per_hour: 120
burst_anomaly_threshold: '>180/min sustained suggests proxy abuse'
production_description: Application gateway forwards authorized requests to APP-CORE business logic.
criticality_to_business: critical
if_disrupted: APP-CORE loses inbound from the legitimate ingress path.
```

### appcore-to-dboltp

`10.2.100.10` → `10.1.200.10:5432/tcp`, cadence: every 30s, criticality: **critical**

```yaml
name: appcore-to-dboltp
src_zone: APP-CORE
src_ip: 10.2.100.10
dst_zone: DB-OLTP
dst_ip: 10.1.200.10
dst_port: 5432
proto: tcp
cadence: every 30s
expected_volume_per_hour: 120
burst_anomaly_threshold: '>180/min sustained suggests query-loop bug or exfiltration probe'
production_description: APP-CORE issues OLTP transactions (SELECT users / SELECT orders / INSERT log / UPDATE session) against DB-OLTP.
criticality_to_business: critical
if_disrupted: Application cannot read/write business state. Cascade outage to user-facing operations.
```

### appcore-to-worker

`10.2.100.10` → `10.4.100.10:8082/tcp`, cadence: every 45s, criticality: **high**

```yaml
name: appcore-to-worker
src_zone: APP-CORE
src_ip: 10.2.100.10
dst_zone: WORKER
dst_ip: 10.4.100.10
dst_port: 8082
proto: tcp
cadence: every 45s
expected_volume_per_hour: 80
production_description: APP-CORE dispatches async jobs to WORKER tier.
criticality_to_business: high
if_disrupted: Async job pipeline halts; backlog accumulates.
```

### appcore-to-dbanalytics-report

`10.2.100.10` → `10.3.200.10:5432/tcp`, cadence: every 60s, criticality: **medium**

```yaml
name: appcore-to-dbanalytics-report
src_zone: APP-CORE
src_ip: 10.2.100.10
dst_zone: DB-ANALYTICS
dst_ip: 10.3.200.10
dst_port: 5432
proto: tcp
cadence: every 60s
expected_volume_per_hour: 60
production_description: APP-CORE runs report queries against analytics tier.
criticality_to_business: medium
if_disrupted: Reports stale; analytics dashboards degrade.
```

### worker-to-dboltp-persist

`10.4.100.10` → `10.1.200.10:5432/tcp`, cadence: every 45s, criticality: **high**

```yaml
name: worker-to-dboltp-persist
src_zone: WORKER
src_ip: 10.4.100.10
dst_zone: DB-OLTP
dst_ip: 10.1.200.10
dst_port: 5432
proto: tcp
cadence: every 45s
expected_volume_per_hour: 80
production_description: WORKER persists async job results to DB-OLTP.
criticality_to_business: high
if_disrupted: Job results lost; downstream consumers degraded.
```

### dboltp-to-dbanalytics-replicate

`10.1.200.10` → `10.3.200.10:5432/tcp`, cadence: every 2 minutes, criticality: **medium**

```yaml
name: dboltp-to-dbanalytics-replicate
src_zone: DB-OLTP
src_ip: 10.1.200.10
dst_zone: DB-ANALYTICS
dst_ip: 10.3.200.10
dst_port: 5432
proto: tcp
cadence: every 2 minutes
expected_volume_per_hour: 30
production_description: DB-OLTP replicates to DB-ANALYTICS (ETL). Sole legitimate DB-OLTP outbound.
criticality_to_business: medium
if_disrupted: Analytics tier becomes stale.
```

## Management plane flows

### monitoring-scrape-endpoints

`10.4.200.10` → 6 dst, cadence: every 60s per dst, criticality: **high**

```yaml
name: monitoring-scrape-endpoints
src_zone: MONITORING
src_ip: 10.4.200.10
destinations:
- 10.1.100.10:80    # WEB
- 10.3.100.10:8080  # APP-GW
- 10.2.100.10:8090  # APP-CORE
- 10.4.100.10:8082  # WORKER
- 10.1.200.10:5432  # DB-OLTP
- 10.3.200.10:5432  # DB-ANALYTICS
proto: tcp
cadence: every 60s per dst
expected_volume_per_hour: 360
production_description: MONITORING tier scrapes service-health/metrics from all data + app tiers. Read-only by role.
criticality_to_business: high
if_disrupted: Observability blind. Agent loses passive service-health source.
```

### management-compliance-ssh-audit

`10.2.50.10` → `rotating WEB/APP-GW/APP-CORE/WORKER:22/tcp`, cadence: every 2 minutes (rotating)

```yaml
name: management-compliance-ssh-audit
src_zone: MGT
src_ip: 10.2.50.10
dst_zones: [WEB, APP-GW, APP-CORE, WORKER]
dst_port: 22
proto: tcp
cadence: every 2 minutes (rotating)
expected_volume_per_hour: 30
burst_anomaly_threshold: '>5/min on same dst suggests credential brute-force'
production_description: MGT performs periodic compliance SSH login across managed zones (workload tiers).
criticality_to_business: high
if_disrupted: Loss of compliance audit posture.
```

### management-application-log-retrieval

`10.2.50.10` → `10.2.100.10:22/tcp`, cadence: every 5 minutes

```yaml
name: management-application-log-retrieval
src_zone: MGT
src_ip: 10.2.50.10
dst_zone: APP-CORE
dst_ip: 10.2.100.10
dst_port: 22
proto: tcp
cadence: every 5 minutes
expected_volume_per_hour: 12
production_description: MGT retrieves application logs from APP-CORE for centralized aggregation.
criticality_to_business: medium
if_disrupted: Logs not centralized; incident analysis degraded.
```
