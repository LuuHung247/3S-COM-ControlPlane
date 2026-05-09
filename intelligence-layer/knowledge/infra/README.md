# `knowledge/infra/` — Machine-Parsable Knowledge Base

This directory holds the **single source of truth** for the agent's structured knowledge:
trust zones, workload assets, leaf switches, traffic baselines, policy matrix, Suricata
SIDs, kill chains, enforcement-plane contract, and network invariants.

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
| `zones.md` | 4 trust zones | `Zone` |
| `assets.md` | 4 workload hosts | `Asset` (with nested `Service`) |
| `leafs.md` | 2 SONiC leafs | `Leaf` |
| `baselines.md` | Application + management traffic flows + anomalous patterns | `TrafficPattern` + constants |
| `policy-matrix.md` | 12 zone-pair verdicts | `(src_zone, dst_zone) → ALLOW/DENY` |
| `sids.md` | 8 Suricata signatures | `SidDetection` |
| `kill-chains.md` | 4 multi-stage adversary playbooks | `KillChain` (with nested `KillChainStage`) |
| `enforcement-plane.md` | SF REST endpoint contracts, gotchas, failure modes, RBAC | mixed |
| `invariants.md` | NEVER_BLOCK CIDRs, allowed actions, comment prefixes | hard safety constants |

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
