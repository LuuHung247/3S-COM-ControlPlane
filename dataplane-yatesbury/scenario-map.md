# Yatesbury Scenario → SID → Eval Mapping

Reference cho tất cả 8 scenarios Yatesbury (NetVigil NSDI'24 Table 3).

## Mapping table

| # | Scenario | Attacker | Target | Suricata SID(s) | KG pattern | Agent expect | Eval wrapper |
|---|---|---|---|---|---|---|---|
| 1 | Vertical port scan | APP (10.2.100.10) | DB:1-1000 | **9000040** (≥20 SYN/30s) | `vertical_port_scan` | log_only | `eval_yates_vertical_scan.py` |
| 2 | SYN flood DoS | APP | DB:5432 | **9000043** (≥200 SYN/10s) | `syn_flood_dos` | DROP | `eval_yates_syn_flood_dos.py` |
| 3 | SYN flood DDoS | APP + WEB | DB:5432 | **9000044** ×2 (per-src 50/10s) | `syn_flood_ddos` | DROP | `eval_yates_syn_flood_ddos.py` |
| 4 | UDP DDoS | APP + WEB | DB:53 | **9000045** (≥500 UDP/10s by_dst) | `udp_ddos` | DROP | `eval_yates_udp_ddos.py` |
| 5 | Distributed TCP scan | APP + WEB | many hosts/ports | **9000041** (per-src 5/60s key ports) | `distributed_port_scan` | log_only | `eval_yates_distributed_scan.py` |
| 6 | Infection Monkey | APP | DB scan + lateral probe | **9000040** + **9000052** chain | `infection_monkey_chain` | DROP | `eval_yates_infection_monkey.py` |
| 7 | C&C beacon | APP | 8.8.8.8:443 | **9000046** (5 small SYN/300s) | `c2_beacon` | DROP | `eval_yates_c2_beacon.py` |
| 8 | Unauthorized DB | WEB (reuses existing) | DB:5432 | **9000001** + **9000051** | `cross_zone_violation_web_to_db` | DROP | `eval_yates_unauth_db.py` |

## Suricata threshold notes

- SID 9000040 fires after **20+ SYN/30s same src** — nmap `-p1-100` triggers easily.
- SID 9000043 needs **200 SYN-without-ACK / 10s same src** — `hping3 --flood -q` reaches kernel rate.
- SID 9000044 needs **50 SYN-without-ACK / 10s per (src, dst) pair** — slower hping3 (`-i u20000`).
- SID 9000045 needs **500 UDP / 10s same dst** — UDP `--flood` works.
- SID 9000041 needs **5 SYN to key ports / 60s same src** — `ncat -z` probe sequence triggers.
- SID 9000052 needs **10 SYN to exploit ports / 60s same src** — monkey iterates 8 ports × 3 hosts = 24.
- SID 9000046 needs **5 small (<200B) SYN / 300s lab→external same src** — 8 beacons over 4 min.
- SID 9000048/9/50 are content-match (no threshold) — fires on first matching packet.

## Attack-script flag protocol

Each attacker script checks for a flag file `/tmp/compromised-yates-<name>`. If
absent, exits no-op. Flag is set by MGT scenario controller via SSH:

```
[MGT compromise-yates-<name>.sh]
        │ SSH
        ▼
[APP/WEB host: touch /tmp/compromised-yates-<name>]
        │ wait next cron tick (≤60s)
        ▼
[APP/WEB cron runs yates-<name>.sh — flag present → attack fires]
        │ network actions
        ▼
[Suricata captures → fires SID via tc clsact mirror on LEAF]
        │
        ▼
[ids-agent → intel-layer SSE → agent reason → SF push DROP rule]
```

`restore-yates.sh` removes all flags via SSH to APP+WEB → next cron tick no-op.

## Cron strategy

Cron runs every minute. Scenarios that need 2 ticks per minute (for higher
volume) can add `* * * * * sleep 30; /usr/local/bin/yates-<name>.sh` as a 2nd
entry. Currently only baseline-noise/attacker patterns use this — yates uses
1 tick/min which is sufficient for thresholds.

## SSH dependency

MGT scenario controllers SSH to APP (10.2.100.10) and WEB (10.1.100.10) using
key-based auth (configured in base bootstrap). If SSH fails:
- Verify sshd running: `ssh root@10.2.100.10 'echo OK'` từ MGT
- Re-run baseline bootstrap on host (web-host.sh hoặc app-host.sh)

## Coordinated scenarios

`yates-synddos`, `yates-udpddos`, `yates-distscan` set flags on **both** APP
and WEB simultaneously. Both cron ticks fire within the same minute → Suricata
sees concurrent multi-source contributions → fires SID per source. Agent's
job: correlate concurrent SIDs (same dst, multiple srcs, short window) to
infer DDoS/distributed-scan posture.

## Cleanup between trials

Eval harness (`eval_iid.py`) calls `restore-<name>.sh` between trials. For
yates scenarios, all 8 wrappers point to `restore-yates.sh` which wipes ALL
yates flags. Side effect: if you triggered yates-vscan then yates-monkey
back-to-back, the restore between trials disarms both — clean state.
