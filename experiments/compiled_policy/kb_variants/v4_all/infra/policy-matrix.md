# Zone-to-Zone Policy Matrix (V2 — 8×8)

Explicit ALLOW/DENY per directed zone pair. Pairs not listed default to DENY
(deny-by-default). Reply traffic of any ALLOW flow is permitted via stateful conntrack
(`-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT` at chain head).

| Source ↓ \ Dest → | WEB | APP-GW | APP-CORE | WORKER | DB-OLTP | DB-ANLT | MON | MGT |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| **WEB** | — | A | D | D | D | D | D | D |
| **APP-GW** | D | — | A | D | D | D | D | D |
| **APP-CORE** | D | D | — | A | A | A | D | D |
| **WORKER** | D | D | D | — | A | D | D | D |
| **DB-OLTP** | D | D | D | D | — | A | D | D |
| **DB-ANALYTICS** | D | D | D | D | D | — | D | D |
| **MONITORING** | A | A | A | A | A | A | — | D |
| **MGT** | A | A | A | A | A | A | A | — |

A = ALLOW, D = DENY. 20 ALLOW cells + 36 DENY cells + 8 diagonal (intra-zone, n/a) = 64.

## Canonical data — 20 ALLOW cells (rest = DENY by default)

```yaml
policy_matrix:
# Legitimate east-west chain
- src_zone: WEB
  dst_zone: APP-GW
  verdict: ALLOW
- src_zone: APP-GW
  dst_zone: APP-CORE
  verdict: ALLOW
- src_zone: APP-CORE
  dst_zone: WORKER
  verdict: ALLOW
- src_zone: APP-CORE
  dst_zone: DB-OLTP
  verdict: ALLOW
- src_zone: APP-CORE
  dst_zone: DB-ANALYTICS
  verdict: ALLOW
- src_zone: WORKER
  dst_zone: DB-OLTP
  verdict: ALLOW
- src_zone: DB-OLTP
  dst_zone: DB-ANALYTICS
  verdict: ALLOW
# MONITORING → 6 zones (scrape; no MGT, no MON itself)
- src_zone: MONITORING
  dst_zone: WEB
  verdict: ALLOW
- src_zone: MONITORING
  dst_zone: APP-GW
  verdict: ALLOW
- src_zone: MONITORING
  dst_zone: APP-CORE
  verdict: ALLOW
- src_zone: MONITORING
  dst_zone: WORKER
  verdict: ALLOW
- src_zone: MONITORING
  dst_zone: DB-OLTP
  verdict: ALLOW
- src_zone: MONITORING
  dst_zone: DB-ANALYTICS
  verdict: ALLOW
# MGT → 7 zones (admin; everywhere except itself)
- src_zone: MGT
  dst_zone: WEB
  verdict: ALLOW
- src_zone: MGT
  dst_zone: APP-GW
  verdict: ALLOW
- src_zone: MGT
  dst_zone: APP-CORE
  verdict: ALLOW
- src_zone: MGT
  dst_zone: WORKER
  verdict: ALLOW
- src_zone: MGT
  dst_zone: DB-OLTP
  verdict: ALLOW
- src_zone: MGT
  dst_zone: DB-ANALYTICS
  verdict: ALLOW
- src_zone: MGT
  dst_zone: MONITORING
  verdict: ALLOW
- src_zone: APP-CORE
  dst_zone: PAYMENTS
  verdict: ALLOW
- src_zone: PAYMENTS
  dst_zone: DB-OLTP
  verdict: ALLOW
- src_zone: MONITORING
  dst_zone: PAYMENTS
  verdict: ALLOW
- src_zone: MGT
  dst_zone: PAYMENTS
  verdict: ALLOW
```

## Key invariants encoded by this matrix

- **WEB must traverse APP-GW** — no direct WEB→APP-CORE or WEB→DB.
- **APP-CORE is the only zone allowed to talk to BOTH databases** (DB-OLTP for transactions, DB-ANALYTICS for reports).
- **WORKER is restricted to DB-OLTP** — no cross-tier to DB-ANALYTICS (only APP-CORE writes analytics).
- **DB-OLTP is a near-sink** — only allowed outbound is DB-ANALYTICS (replication/ETL).
- **DB-ANALYTICS is a pure sink** — zero allowed outbound; any init = sink-role violation.
- **MONITORING is read-only observer** — may reach all data tiers but NEVER MGT (control plane segregation).
- **MGT has universal access** by compliance design except itself (intra-zone is irrelevant).
