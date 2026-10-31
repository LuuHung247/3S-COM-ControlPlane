# S12 — Public-dataset replay onto the BIZM 8-zone testbed (spec for the dataplane)

Owner: dataplane agent (GNS3 10.10.6.238). Evaluator: control-plane harness
`zerotrust/experiments/s12_replay/s12_replay_eval.py` on master (.231).

## 1. Goal
Feed the BIZM agent real IDS alerts produced by real, labelled traffic from a public
dataset, re-addressed onto the permitted and denied paths of our 8x8 policy matrix, so that
results are reproducible and not author-designed. The original dataset label is the ground
truth; the policy verdict of the mapped path is recorded alongside it.

## 2. Constraints (unchanged)
- Do not modify the 29 custom SIDs, V2 controllers, policy matrix, tc-mirred, SF, host IP/zone.
- Datasets are downloaded through the server (no permanent NAT). Large files live under
  `/data/datasets/` on gns3vm; only manifests, scripts and docs go under `/3s-com/s12/`.
- Baseline cron traffic (MGT audit, MON scrape, web-to-appgw proxy) keeps running during replay.
- Every Suricata restart is announced with a UTC time.

## 3. Dataset
- Primary: CIC-IDS2017 (pcaps + flow-label CSVs, e.g. the Thursday web-attack day and benign
  traffic from the same capture). Optional second source: UNSW-NB15 (pcaps + ground-truth CSV).
- Record in `/3s-com/s12/DATASET.md`: dataset name, version, download URL, file names,
  SHA-256 of every file used.

## 4. Session selection
1. From the label CSV, take sessions (5-tuple + time window) whose client/server roles can be
   mapped to one edge of our matrix:
   - web client → web/API server        → WEB→APP-GW:8080 or APP-GW→APP-CORE:8090
   - application → database server      → APP-CORE→DB-OLTP:5432, WORKER→DB-OLTP:5432
   - any internal host → service on a port with no matching edge → a DENY path
     (e.g. WEB→DB-OLTP:5432) — used as denied-path controls
   Sessions whose roles cannot be mapped are dropped and counted in the report.
2. Per mapped path, sample with a fixed seed (record it) up to 10 malicious and 10 benign
   sessions. Keep every attack category the dataset offers on that path; do not hand-pick.
3. Extract each session to its own pcap (tshark/editcap filter on the 5-tuple and the CSV
   time window, both directions).

## 5. Mapping table — `/3s-com/s12/manifest.csv`
One row per session, header exactly:

```
session_id,dataset,orig_file,orig_label,orig_category,orig_src,orig_dst,orig_dport,lab_path,lab_src,lab_dst,lab_dport,policy_verdict,label_binary,pcap,pcap_sha256
```

- `orig_label`/`orig_category`: verbatim from the dataset.
- `lab_path`: e.g. `WEB->APP-GW:8080`. `policy_verdict`: ALLOW or DENY from the 8x8 matrix.
- `label_binary`: `malicious` if the dataset label is any attack class, else `benign`.
- Each original IP maps to exactly one lab host for the whole session (client → source zone
  primary host, server → destination zone primary host).

## 6. Re-addressing
- `tcprewrite`: map client/server IPs to `lab_src`/`lab_dst`, map the server port to
  `lab_dport` (client ports unchanged), and recompute checksums (`--fixcsum`).
- Keep packet timing; cap any single session at 60 s of replay (truncate, note it in the row).

## 7. Replay entry point — `/3s-com/s12/replay.sh <session_id>`
- Replays that session's rewritten pcap so the packets traverse a LEAF ingress port covered
  by tc-mirred (the IDS must see it exactly as live traffic).
- Before replay: append a marker line (POST `/s12/runs` or write `runs.jsonl`):
  `{"run_id","session_id","label_binary","lab_path","lab_src","lab_dst","lab_dport","t_start"}`
- After replay: update the same run with `t_end` and print `S12_DONE <session_id>` on stdout.
- Exit non-zero on any failure; never leave a replay running.

The control-plane harness calls `replay.sh` over SSH, one session at a time, and resets the
agent and agent rules between sessions.

## 8. IDS reassembly
Mirror is one-directional: enable `stream.async-oneside: true` and `stream.midstream: true`
first and re-run the V2 regression (9000072/9000012 must fire again). Only if insufficient,
propose two-way mirroring — that touches SONiC and needs the user's confirmation.

## 9. Validation before READY
Replay every session once and fill `/3s-com/s12/validation.csv`:

```
session_id,label_binary,lab_path,n_alerts,sids,categories,has_http,has_flow,replay_ok
```

Sessions with zero alerts stay in the manifest and are reported as IDS misses (detection
layer, not agent). Report totals per path and label, RAM before/after, Suricata rule count.
