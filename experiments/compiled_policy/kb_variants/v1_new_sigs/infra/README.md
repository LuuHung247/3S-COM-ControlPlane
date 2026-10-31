# `knowledge/infra/` — Machine-Parsable Knowledge Base (V2)

This directory holds the **single source of truth** for the agent's structured knowledge:
trust zones, workload assets, leaf switches, traffic baselines, policy matrix, Suricata
SIDs, kill chains, enforcement-plane contract, and network invariants.

**V2 (2026-05-31)**: updated for 2-spine / 4-leaf / **8-zone / 16-host** Clos DCN.
All entity counts below reflect V2 state.

## Format

Each `.md` file is **hybrid** — markdown prose for human readers + ` ```yaml ` code blocks
for the deterministic parser. The YAML blocks are canonical; prose context is rendered
around them so the file reads as documentation.

The parser (`src/core/knowledge_parser.py`) extracts every YAML block, validates each
against a Pydantic schema, then ETLs the result into Neo4j. Reads at runtime go through
Neo4j, not these files (the files are the *authoring* layer; Neo4j is the *runtime* store).

## Files

| File | Entities | Pydantic schema |
|---|---|---|
| `zones.md` | **8 trust zones** (V2: WEB, APP-GW, APP-CORE, WORKER, DB-OLTP, DB-ANALYTICS, MONITORING, MGT) | `Zone` |
| `assets.md` | **8 canonical workload hosts** (one per zone; each has a `.10` primary + `.11` secondary) | `Asset` (with nested `Service`) |
| `leafs.md` | **4 SONiC leafs** (LEAF-1..4, each owns 2 zones) | `Leaf` |
| `baselines.md` | Application + management traffic flows + anomalous patterns + statistical bounds + time-of-day multipliers (V2: 10 cron-driven flows) | `TrafficPattern` + constants |
| `policy-matrix.md` | **56 zone-pair verdicts (20 ALLOW + 36 DENY)** of the 8×8 matrix | `(src_zone, dst_zone) → ALLOW/DENY` |
| `sids.md` | **29 Suricata SIDs (V2)** — 13 V2 policy violations + 5 recon + 3 flooding + 3 C2 + 3 DB content + 2 audit | `SidDetection` |
| `threat-patterns.md` | **8 threat classes / 22+ flow-keyed patterns** covering Yatesbury benchmark + V2 lab scenarios | `ThreatPattern` |
| `severity-scoring.md` | Deterministic point-based severity rubric, action mapping, confidence calibration, hard overrides | `SeverityRubric` |
| `flow-features.md` | Feature extraction protocol (9 features per IP pair × 2-min window) following NetVigil Table 2 | `FlowFeatureSet` |
| `kill-chains.md` | **7 multi-stage adversary playbooks** (V2: web-breach, appgw-skip, appcore-pivoting, worker-lateral, mgt-cred, db-exfil, mon-breach) | `KillChain` (with nested `KillChainStage`) |
| `enforcement-plane.md` | SF REST endpoint contracts across **4 LEAFs**, gotchas, failure modes, RBAC | mixed |
| `invariants.md` | NEVER_BLOCK CIDRs (V2: +4 new zone gateways + 2 new LEAF mgmt + 2 MON hosts), allowed actions, comment prefixes | hard safety constants |

## Pure-log mode (2026-05-14 onward; V2 SIDs 2026-05-31)

The agent operates without spoon-feeding Suricata SID alerts. Instead it consumes raw
`eve.json type:flow` events and reasons from:

1. **`threat-patterns.md`** — match flow signature → identify threat class
2. **`baselines.md`** — compare observed rate against statistical bounds
3. **`severity-scoring.md`** — quantitative scoring → P-level + action
4. **`policy-matrix.md`** — verify zone-pair verdict (hard policy gate, 8×8 matrix)
5. **`invariants.md`** — apply hard overrides (NEVER_BLOCK, allowed actions)

`sids.md` remains as legacy reference; V2 ruleset (29 SIDs) is documented there for
control-plane integration teams using SF→eve.json correlation.

## Workflow

1. Edit the `.md` file (zone CIDR change, new SID, etc.)
2. Run `python scripts/sync_knowledge_to_neo4j.py` (parses + writes Neo4j)
3. Restart `intelligence-layer` container (RAM cache reloads from Neo4j)

The parser fails closed — invalid YAML or schema violation aborts sync without touching
Neo4j. Type safety preserved by Pydantic validation at parse time.

## Why this layout (not pure YAML)

- Markdown is git-tracked, code-reviewed, renders nicely on GitHub/IDE
- Single file = data + human context (no drift between docs and code)
- YAML blocks parsed deterministically — no LLM extraction, no hallucination risk
- Pydantic validation guarantees parsed entities match schema before reaching Neo4j

For *unstructured* security knowledge (NIST 800-207, CIS benchmarks, threat intel),
see future `knowledge/standards/` — that layer uses LLM extraction.
