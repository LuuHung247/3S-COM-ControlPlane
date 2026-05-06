# Eval Memory — Stateful baseline (memory under test)

## Question

Khi cùng 1 attacker (cùng src_ip) tấn công lặp lại N lần, agent memory (past-incident retrieval, asset reputation, kill-chain correlation) có **thực sự giúp ích** không? Cụ thể:

- Confidence có **tăng** dần qua các runs?
- Latency / reasoning có **giảm** dần (vì agent có context để skip thinking)?
- Pattern recognition có làm decision **chính xác hơn** ở runs sau?

## Design

Y hệt `eval_iid.py` về scenario, attack trigger, metrics — **chỉ khác 1 chỗ duy nhất** trong `reset()`:

| Reset action | `eval_iid` | `eval_memory` |
|--------------|:--:|:--:|
| Disarm `compromise-web.sh` | ✓ | ✓ |
| Delete agent-pushed SF rules | ✓ | ✓ |
| Flush Redis DB 0 (rate limiter / cache) | ✓ | ✓ |
| **TRUNCATE Postgres `decisions`** | **✓** | **✗ KEEP** |
| Reset intel-layer rate limiter | ✓ | ✓ |
| Preserve Redis DB 1 (FE Monitor buffer) | ✓ | ✓ |
| Preserve Postgres `decisions_history` | ✓ | ✓ |

→ Run N đọc `decisions` table có ≥ N-1 rows (1 row mỗi run trước). Agent's past-incident retrieval (semantic + asset reputation + kill-chain) sẽ pull những rows này về làm context.

## Why we still delete agent rules between runs

Nếu để rule cũ tồn tại, LEAF iptables sẽ DROP gói SYN ngay tại data plane → Suricata không thấy traffic → không có alert → agent không được invoke → không đo được gì.

→ Phải xoá rule giữa runs để attack có thể fire lại + tạo alert mới.

## Metrics

Cùng schema với `eval_iid` (xuất xlsx + json):

| Metric | Ý nghĩa trong context memory |
|--------|------------------------------|
| `mttd_s` | Time-to-detect; không bị memory ảnh hưởng (Suricata-side) |
| `t_alert_to_decision_s` | Agent processing time; **kỳ vọng giảm** ở runs sau (cached embeddings, shorter reasoning) |
| `enforce_latency_ms` | Total LLM + tools latency; **kỳ vọng giảm** ở runs sau |
| `confidence` | LLM self-confidence; **kỳ vọng tăng** ở runs sau |
| `enforcement_correct` | src_ip đúng — sanity check, kỳ vọng 100% mọi run |

## Headline output

Cuối eval có panel **memory effect** — so trực tiếp Run 1 (cold) vs Run N (warm):

```
╭─ memory effect ──────────────────────────────────╮
│ Run 1 (cold memory) → Run N (warm memory)       │
│   MTTD (s)              3.50s → 3.40s   ↓ -2.9% │
│   M1 Alert→Decision (s)  6.80s → 4.20s  ↓ -38%  │
│   Agent latency (ms)    7200ms → 4800ms ↓ -33%  │
│   Confidence              0.92 → 0.97   ↑ +5%   │
╰──────────────────────────────────────────────────╯
```

Lower latency + higher confidence ở runs sau ⇒ **memory works**.

## Pitfalls / interpretation guide

| Observation | Có nghĩa là |
|-------------|------------|
| Confidence flat across all runs | Memory không được retrieval pull về, hoặc prompt không đưa vào context |
| Latency flat (không giảm) | Memory được retrieve nhưng agent vẫn re-reason from scratch |
| MTTD dao động lớn | Suricata-side noise (cron `attacker-web.sh`) hoặc lab busy |
| Run 1 fail, Run 2..N pass | Cold-start issue — first decision tạo memory cho subsequent runs |
| Confidence tăng nhưng action thay đổi sai (e.g., DROP→DRY_RUN) | Memory đang gây over-confidence sai → cần kiểm tra retrieval relevance |

## How to run

```bash
cd /home/dis/deploy/zerotrust/experiments
python3 eval_memory.py
```

Constants ở đầu file (cùng schema với `eval_iid.py`):

```python
RUNS = 10                               # số runs liên tiếp
DURATION_SECONDS = 120                  # timeout mỗi run
ATTACKER_IP = "10.1.100.10"             # web-01 (cùng IP qua các runs để build memory)
TARGET_SID = 9000001                    # WEB→DB lateral movement
```

Output:
```
results/eval_memory_<timestamp>.xlsx   # per-run table + summary stats
results/eval_memory_<timestamp>.json   # raw RunResult dicts
```

## Recommended workflow

1. **Chạy `eval_iid.py` trước** — baseline i.i.d. (memory off)
2. **Chạy `eval_memory.py` ngay sau** — same scenario, memory on
3. **So 2 file xlsx** — confidence/latency của eval_memory tốt hơn eval_iid bao nhiêu = giá trị thực tế của memory architecture cho production
