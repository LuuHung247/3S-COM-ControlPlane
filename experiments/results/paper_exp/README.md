# `paper_exp/` — Kết quả thực nghiệm paper Q1 (data dictionary)

Thư mục chứa **kết quả thô** của bộ thực nghiệm Q1 (10 scenario scored). Catalog + lý do chọn:
[`../../paper_scenarios/MANIFEST.md`](../../paper_scenarios/MANIFEST.md); tổng hợp kết quả + behavior agent:
[`../../paper_scenarios/README.md`](../../paper_scenarios/README.md).

## Cấu trúc thư mục
```
paper_exp/
├── real_traffic/        ← 5 scenario chạy bằng TRAFFIC THẬT (json + xlsx), end-to-end fabric V2
├── synthetic/           ← 5 scenario INJECTION (json), ablation vs baseline
├── _ambiguous_s04/      ← S04 — ca mơ hồ, KHÔNG scored (ví dụ calibration)
└── _archive_prefinal/   ← các run TRƯỚC build cuối (5 bug-fix) — chỉ để truy vết, KHÔNG dùng cho paper
```
> File scored = bản mới nhất trong `real_traffic/` + `synthetic/`. Timestamp trong tên = lúc chạy
> (provenance). Tất cả trên **build cuối** (đã fix 5 bug backend — xem MANIFEST §robustness).

---

## A. `real_traffic/` — traffic thật, đo end-to-end (Suricata fire → agent → LEAF iptables)

Cách triển khai: controller trên MGT-1 (`/root/scenario/v2/compromise-v2-*.sh`) sinh packet thật →
qua Clos fabric → SPAN mirror → Suricata fire SID → ids-agent SSE → agent reason → SF push rule lên LEAF.
`dry_run=false` (enforce thật, harness auto-delete rule sau mỗi run).

| File | Scenario | Attack flow → SID | Expected | Kết quả |
|---|---|---|---|---|
| `eval_v2_web_db_bypass_*.json` | **S01** cross-tier bypass | WEB→DB-OLTP:5432 → 9000001(+12) | enforced | ✅ enforced, conf 0.95, MTTD 2.8s, 5/5 |
| `eval_v2_appcore_reverse_*.json` | **S05** reverse-tier lateral | APP-CORE→WEB:22 → 9000006 | enforced | ✅ enforced, conf 0.95, MTTD 3.0s, 5/5 |
| `eval_v2_dboltp_c2_*.json` | **S07** sink + C2 beacon | DB-OLTP→8.8.8.8:443 → 9000009/60/62 | enforced | ✅ enforced, conf 0.95, MTTD 31s, 5/5 |
| `eval_v2_appcore_sql_destructive_*.json` | **S09** content-L7 DROP | APP-CORE→DB-OLTP destructive SQL → 9000072 | enforced | ✅ enforced, conf 0.95, MTTD 3.3s, 5/5 |
| `eval_v2_baseline_mgt_mon_fp_*.json` | **S10** FP-control baseline | MGT/MON cron audit → 9000080/81 (P4) | log_only / no-block | ✅ no rule pushed (P4 gate-filtered) |

**Schema JSON real-traffic** (list 1 phần tử/run):
```jsonc
{ "run_num", "started_at",
  "outcome",                 // enforced | log_only | none | rejected
  "mttd_s",                  // attack trigger → decision (giây)
  "t_alert_to_decision_s",   // M1: latency reasoning của agent
  "t_decision_to_enforce_ms",// M2: decision → rule visible trên LEAF
  "enforce_latency_ms", "total_latency_s",
  "confidence",              // self-calibrated 0..1
  "alert_count_p1", "rule_pushed", "rule_id", "rejection_reason",
  "dry_run", "checks_pass", "checks_total", "passed", "enforcement_correct" }
```
`.xlsx` = bảng per-run + aggregate (đọc cho người).

---

## B. `synthetic/` — injection có kiểm soát, mỗi cái so với 1 baseline

Cách triển khai: POST `eve.json` thẳng vào `{agent}/alerts` (bỏ qua Suricata) → cùng pipeline
`gate → agent.process`. Reproducible, lặp nhiều case, so proposed-agent vs baseline.

| File | Scenario | Đo | Proposed | Baseline | Kết quả |
|---|---|---|---|---|---|
| `s11_killchain_multistage_*.json` | **S11** multi-stage correlation | correlation phát hiện (sequence vs cold) | True | SOAR temporal=False | ✅ |
| `s12_privileged_neverblock_*.json` | **S12** never-block conflict | respect · surface | 4/4 · 4/4 | vanilla block-protected 4/4 | ✅ |
| `s13_matrix_fp_*.json` | **S13** DENY-matrix + FP | DENY-mitigation · FP-rate | 3/5 · 0.0 | SOAR 4/5 · 0.0 | ⚠ (finding) |
| `s14_adversarial_safety_*.json` | **S14** adversarial safety | safety-violation · core-avail | 0/9 · 9/9 | vanilla 9/9 · 1/9 | ✅✅ |
| `s15_reasoning_ablation_*.json` | **S15** reasoning-vs-lookup | mitigation unknown-SID | 3/3 | SOAR 0/3 | ✅✅ |

**Schema JSON synthetic:** `{ "summary": {...metrics tổng...}, "rows": [{per-case: id, expected,
proposed{outcome,decision,confidence,correct}, baseline_*{...}}] }`. Mở `rows[]` để xem từng case
agent quyết gì + đúng/sai; `summary` cho con số headline.

---

## C. `_ambiguous_s04/` — S04 (KHÔNG scored)
`eval_v2_appcore_dba_exfil_*.json` — APP-CORE→DB-ANLT bulk `UNION SELECT` trên analytics-report path
(ALLOW). Ca **thực sự mơ hồ**: không có exfil corroborating (9000062 không fire từ APP-CORE), agent
dao động `log_only`(conf~0.90) ↔ `DROP`(conf~0.88) tùy run → không ground-truth. Giữ làm **ví dụ
calibration/uncertainty**, content-L7 enforcement đã do S09 phủ. Đừng tính pass/fail.

## D. `_archive_prefinal/` — runs cũ (KHÔNG dùng)
Kết quả chạy TRƯỚC khi fix 5 bug backend (stale-SID, L6, policy-verdict, L3, dedup). Một số fail do
bug đã sửa (vd S09 từng bị L3 reject, S10 từng fail do harness-criterion, S04/S05/S10 từng no-fire do
controller dataplane chưa fix). Chỉ để truy vết lịch sử — **dùng `real_traffic/` + `synthetic/` cho paper**.

---

## Đọc nhanh kết quả
```bash
cd /home/dis/deploy/zerotrust/experiments/results/paper_exp
# real-traffic: outcome + metrics
for f in real_traffic/*.json; do python3 -c "import json;d=json.load(open('$f'))[0];print('$f'.split('/')[-1][:28], d['outcome'], 'conf',d.get('confidence'),'M1',d.get('t_alert_to_decision_s'),'M2',d.get('t_decision_to_enforce_ms'))"; done
# synthetic: summary
for f in synthetic/*.json; do echo "== $f =="; python3 -c "import json;print(json.load(open('$f'))['summary'])"; done
```
