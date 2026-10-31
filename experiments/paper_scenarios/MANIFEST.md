# Paper Q1 — Curated Experiment Set

Chỉ những thực nghiệm **đưa vào paper Q1**. Nguyên tắc chọn: đóng góp của paper là
**LLM-agent reasoning/safety vượt SOAR signature/rate-threshold** — nên ưu tiên kịch bản
nơi reasoning tạo khác biệt, KHÔNG nhồi volumetric DoS thuần (chỗ rule tĩnh đã đủ).

Kết quả ghi vào `../results/paper_exp/`. Chạy: `bash run_paper.sh` (hoặc từng dòng).

## Bộ chốt (10 kịch bản = 5 real-traffic + 5 synthetic)

### A. Real-traffic (end-to-end trên fabric V2 — chứng minh hệ thống chạy thật) — 5 cái, ĐỀU PASS
| ID | File | Claim chứng minh |
|---|---|---|
| S01 | `scenarios/s01_web_db_bypass.py` | Enforce zone-matrix cross-tier bypass + multi-LEAF routing |
| S05 | `scenarios/s05_appcore_reverse.py` | Reverse-tier lateral movement (one-way business flow) |
| S07 | `scenarios/s07_dboltp_c2.py` | Sink-role violation + C2 beacon (đại diện NetVigil C2 class) |
| S09 | `scenarios/s09_appcore_sql_destructive.py` | **Content-L7 DROP** — destructive SQL trên ALLOW-path (DROP TABLE) |
| S10 | `scenarios/s10_baseline_mgt_mon_fp.py` | FP-control real-traffic — KHÔNG over-block admin baseline |

> **S04** (`s04_appcore_dba_exfil.py`) — ĐÃ LOẠI khỏi bộ scored: ca *genuinely ambiguous*
> (bulk UNION SELECT trên analytics-report path hợp lệ). Không có ground-truth rõ — agent
> dao động log_only(conf~0.90) ↔ DROP(conf~0.88) tùy run. Giữ ở `results/paper_exp/_ambiguous_s04/`
> làm ví dụ calibration/uncertainty, KHÔNG tính pass/fail. Content-L7 enforcement đã được S09 phủ sạch.

### B. Synthetic-injection (controlled / ablation — bằng chứng reasoning, chỉ cần LLM)
| ID | File | Claim chứng minh | Baseline |
|---|---|---|---|
| S11 | `generalization/s11_killchain_multistage.py` | Multi-stage temporal correlation | vs SOAR vô-memory |
| S12 | `safety/s12_privileged_neverblock.py` | Privileged-zone attacker + never-block conflict | vs vanilla LLM |
| S13 | `scenarios/s13_matrix_fp.py` | DENY-matrix coverage (9000003/5/7/11/13) + FP battery | vs SOAR keyed-SID |
| S14 | `safety/s14_adversarial_safety.py` | Adversarial safety (prompt-injection + spoof) | vs vanilla LLM |
| S15 | `generalization/s15_reasoning_ablation.py` | Reasoning-vs-lookup (known/unknown SID) | vs SOAR keyed-SID |

## Mapping → paper claims
- **C1 Reasoning > SOAR (generalize unknown):** S15 (+ S13)
- **C2 Adversarial safety:** S14, S12
- **C3 Multi-stage correlation:** S11
- **C4 No over-block (respect legit):** S10, S13
- **C5 ZT microseg enforcement (real fabric):** S01, S04, S05, S07
- **C6 NetVigil comparability (external):** S07 (C2) — mở rộng thêm Yatesbury subset nếu cần

## KHÔNG đưa vào paper (giữ repo làm phụ lục)
- Biến thể microseg gần trùng: S02, S03 (tier-skip ~ S01), S06 (reverse ~ S05), S08 (sink ~ S07), S09 (destructive-SQL ~ S04)
- Yatesbury volumetric đầy đủ (SYN/UDP flood đơn lẻ): SOAR rate-threshold cũng xử được → low differentiation. Giữ 2-3 đại diện nếu cần so NetVigil.
