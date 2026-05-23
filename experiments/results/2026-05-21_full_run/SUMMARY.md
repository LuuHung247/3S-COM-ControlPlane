# Full Experiment Run — 2026-05-21

13 scenario chạy lại tuần tự (1 run/scenario, pre-clean state giữa mỗi run), foreground để verify pipeline end-to-end. Gồm 11 scenario từ run 08:11–08:33 + 2 scenario (09 syn_flood_ddos, 10 udp_ddos) rerun 09:32–09:33 sau fix.

## Tổng kết

| Metric | Value |
|---|---|
| Total scenarios | 13 |
| **Strict PASS** | **13/13 (100%)** |
| LLM Agent failures | **0** (Cerebras zai-glm-4.7 healthy toàn bộ; không 503/timeout/credit) |
| Pipeline FAIL | 0 — Suricata → agent (KG+memory) → SF → LEAF iptables confirmed |
| Avg confidence | 0.91 |
| Avg MTTD (IDS) | 33.25s |
| Avg M1 (alert→decision) | 9.49s |
| Avg M2 (decision→LEAF) | 2.87s |

## Per-scenario results

| # | Scenario | Status | Outcome | MTTD | M1 A→D | M2 D→LEAF | Conf | Checks | Note |
|---|---|---|---|---|---|---|---|---|---|
| 01 | zt_web_db_lateral | ✅ PASS | enforced | 40.6s | 6.71s | 0.98s | 0.95 | 5/5 | WEB→DB:5432 microsegmentation bypass |
| 03 | zt_web_app_burst | ✅ PASS | enforced | 4.1s | 11.94s | 2.04s | 0.85 | 5/5 | 250 conn WEB→APP:8080 rate burst |
| 04 | zt_app_db_burst | ✅ PASS | enforced | 30.9s | 6.71s | 0.61s | 0.88 | 5/5 | 100 conn APP→DB:5432 rate burst |
| 05 | zt_app_db_sql | ✅ PASS | enforced | 30.2s | 6.36s | 1.68s | 0.95 | 5/5 | DROP TABLE content match (destructive SQL) |
| 06 | zt_app_mgt_ssh | ✅ PASS | enforced | 10.6s | 6.35s | 1.19s | 0.92 | 5/5 | APP→MGT:22 cross-zone SSH |
| 07 | yates_vertical_scan | ✅ PASS | enforced | 45.6s | 7.69s | 4.94s | 0.85 | 5/5 | nmap -sS p1-100 vertical port scan |
| 08 | yates_syn_flood_dos | ✅ PASS | enforced | 61.6s | 18.88s | 7.94s | 0.88 | 5/5 | hping3 SYN flood single-src (200/10s) |
| 09 | yates_syn_flood_ddos | ✅ PASS | enforced | 58.7s | 6.82s | 2.94s | 0.95 | 5/5 | APP+WEB SYN flood DDoS → DB:5432 (multi-src) |
| 10 | yates_udp_ddos | ✅ PASS | enforced | 10.9s | 12.52s | 4.72s | 0.95 | 5/5 | WEB UDP flood → DB:53 (500/10s) |
| 11 | yates_distributed_scan | ✅ PASS | enforced | 70.9s | 7.0s | 0.49s | 0.88 | 5/5 | APP+WEB distributed key-port probe |
| 12 | yates_infection_monkey | ✅ PASS | enforced | 0.0s | 9.54s | 4.1s | 0.92 | 5/5 | multi-stage scan+exploit chain |
| 13 | yates_c2_beacon | ✅ PASS | enforced | 64.3s | 12.35s | 1.77s | 0.85 | 5/5 | low-and-slow C2 heartbeat → 8.8.8.8:443 |
| 14 | yates_unauth_db | ✅ PASS | enforced | 3.8s | 10.45s | 3.91s | 0.95 | 5/5 | DB connection from non-APP zone |

## Fix áp dụng cho 2 scenario trước đó FAIL

- **09 syn_flood_ddos** (trước: benign conf 0.72 / IP mismatch): (a) harness multi-IP accept [APP,WEB] cho DDoS đa nguồn; (b) KG SID 9000044 `false_positive_likelihood` medium→low (50 SYN/10s tới DB OLTP = attack, act on single src); (c) M2 LEAF-verify wait 8→20s. → enforced conf 0.95.
- **10 udp_ddos** (trước: outcome=none / IP sai): preset `attacker_ip` 10.2.100.10(APP)→10.1.100.10(WEB) — UDP flood thật launch từ WEB. → enforced conf 0.95.

## Ghi chú

- 5 checks/scenario: (1) P1+ alert fired, (2) agent decision made, (3) outcome enforced/dry_run, (4) rule visible trên SF/LEAF, (5) latency < 30s.
- "rejected" duy nhất trong run gốc là L5 per-IP rate-limit gate (safety by-design), không phải LLM failure.
- Mỗi scenario có file `<NN>_<name>.xlsx` (per-run + aggregate) + `.json` (machine-readable). Tổng hợp ở `AGGREGATE.json`.
