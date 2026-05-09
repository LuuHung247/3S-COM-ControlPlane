# Zone-to-Zone Policy Matrix

Explicit ALLOW/DENY per directed zone pair. Pairs not listed default to DENY.
Reply traffic of any ALLOW flow is permitted via stateful conntrack.

| Source ↓ \ Destination → | WEB | DB | APP | MGT |
|---|---|---|---|---|
| **WEB** | — | DENY | ALLOW | DENY |
| **DB** | DENY | — | DENY | DENY |
| **APP** | DENY | ALLOW | — | DENY |
| **MGT** | ALLOW | ALLOW | ALLOW | — |

## Canonical data

```yaml
policy_matrix:
- src_zone: WEB
  dst_zone: DB
  verdict: DENY
- src_zone: WEB
  dst_zone: APP
  verdict: ALLOW
- src_zone: WEB
  dst_zone: MGT
  verdict: DENY
- src_zone: DB
  dst_zone: WEB
  verdict: DENY
- src_zone: DB
  dst_zone: APP
  verdict: DENY
- src_zone: DB
  dst_zone: MGT
  verdict: DENY
- src_zone: APP
  dst_zone: WEB
  verdict: DENY
- src_zone: APP
  dst_zone: DB
  verdict: ALLOW
- src_zone: APP
  dst_zone: MGT
  verdict: DENY
- src_zone: MGT
  dst_zone: WEB
  verdict: ALLOW
- src_zone: MGT
  dst_zone: DB
  verdict: ALLOW
- src_zone: MGT
  dst_zone: APP
  verdict: ALLOW
```
