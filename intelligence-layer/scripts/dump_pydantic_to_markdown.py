"""Dump current Pydantic constants → knowledge/infra/*.md (markdown + YAML blocks).

Reads the in-code source-of-truth (system_model.ZONES, baselines.ALL_BASELINES,
threat_playbook.SID_DETECTIONS, policy.POLICY_MATRIX, enforcement_plane.*,
invariants.*) and writes one .md file per entity-type into knowledge/infra/.

Each .md file has the form:
    # <title>
    <one-paragraph intro>

    ## <entity name>
    <prose for human reader>

    ```yaml
    <canonical YAML — what the parser reads>
    ```

The YAML blocks are the machine source-of-truth. Prose around them is human context
(rendered together so the file reads as documentation).

After this dump runs once, edit only the .md files. The Pydantic constants will be
removed in a subsequent commit.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from src.core import system_model, baselines, threat_playbook, policy
from src.core import enforcement_plane, invariants


OUT = REPO / "knowledge" / "infra"
OUT.mkdir(parents=True, exist_ok=True)


def _yaml_dump(obj) -> str:
    return yaml.safe_dump(
        obj,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        width=100,
    ).rstrip()


def _block(obj) -> str:
    return f"```yaml\n{_yaml_dump(obj)}\n```"


# ─────────────────────────────────────────────────────────────────────────────
# zones.md
# ─────────────────────────────────────────────────────────────────────────────
def write_zones() -> None:
    parts: list[str] = [
        "# Trust Zones",
        "",
        "Four trust zones partition the datacenter fabric. Each zone has its own CIDR, VLAN,",
        "SVI gateway, trust posture, and criticality. The agent maps every alert IP to a zone",
        "via CIDR membership; zone-pair determines the policy verdict (see `policy-matrix.md`).",
        "",
    ]
    for name, z in system_model.ZONES.items():
        d = z.model_dump()
        # Convert enum values to plain strings
        d["trust_level"] = z.trust_level.value
        d["criticality"] = z.criticality.value
        parts += [
            f"## {name} — {z.purpose.split('.')[0]}",
            "",
            f"CIDR `{z.cidr}` on `{z.leaf}` (VLAN {z.vlan}, SVI {z.svi_gateway}). "
            f"Trust level: **{z.trust_level.value}**, criticality: **{z.criticality.value}**.",
            "",
            _block(d),
            "",
        ]
    (OUT / "zones.md").write_text("\n".join(parts))
    print(f"  ✓ zones.md  ({len(system_model.ZONES)} zones)")


# ─────────────────────────────────────────────────────────────────────────────
# assets.md
# ─────────────────────────────────────────────────────────────────────────────
def write_assets() -> None:
    parts: list[str] = [
        "# Workload Assets",
        "",
        "Each zone hosts exactly one production workload. Single-host-per-zone simplifies",
        "tenant identity: zone CIDR maps 1:1 to a host. Each asset declares its services,",
        "expected traffic neighbors, and blast-radius prose for both 'compromised' and",
        "'blocked' counterfactuals — agents use these to weigh containment vs availability.",
        "",
    ]
    for ip, a in system_model.ASSETS.items():
        d = a.model_dump()
        d["criticality"] = a.criticality.value
        d["data_classification"] = a.data_classification.value
        # services already serialized as list[dict]
        parts += [
            f"## {a.hostname} ({ip})",
            "",
            f"**Zone**: {a.zone}  ·  **Tier**: {a.tier}  ·  "
            f"**Criticality**: {a.criticality.value}  ·  **Data**: {a.data_classification.value}  "
            f"·  **Owner**: {a.owner_team}",
            "",
            f"**Role**: {a.role}",
            "",
            "**If compromised**:",
            "",
            f"> {a.if_compromised_impact}",
            "",
            "**If blocked**:",
            "",
            f"> {a.if_blocked_impact}",
            "",
            _block(d),
            "",
        ]
    (OUT / "assets.md").write_text("\n".join(parts))
    print(f"  ✓ assets.md  ({len(system_model.ASSETS)} assets)")


# ─────────────────────────────────────────────────────────────────────────────
# leafs.md
# ─────────────────────────────────────────────────────────────────────────────
def write_leafs() -> None:
    parts: list[str] = [
        "# Leaf Switches (enforcement points)",
        "",
        "Two SONiC leafs run iptables FORWARD chains; agent-pushed rules land here. Each leaf",
        "owns the SVIs for its attached zones. Cross-leaf policy is defense-in-depth: same",
        "rule applied on both leafs so source-routing bypass at one leaf still hits the other.",
        "",
    ]
    for name, l in system_model.LEAFS.items():
        d = l.model_dump()
        parts += [
            f"## {name}",
            "",
            f"Mgmt IP `{l.mgmt_ip}`. Zones: {', '.join(l.zones)}. Role: {l.role}",
            "",
            _block(d),
            "",
        ]
    (OUT / "leafs.md").write_text("\n".join(parts))
    print(f"  ✓ leafs.md  ({len(system_model.LEAFS)} leafs)")


# ─────────────────────────────────────────────────────────────────────────────
# baselines.md
# ─────────────────────────────────────────────────────────────────────────────
def write_baselines() -> None:
    parts: list[str] = [
        "# Production Traffic Baselines",
        "",
        f"Steady-state east-west volume: ~{baselines.STEADY_STATE_FLOWS_PER_MINUTE} flows/minute. "
        f"MGT audit emissions ~{baselines.MGT_AUDIT_ALERT_RATE_PER_MINUTE}/minute (SID 9000020) are",
        "REQUIRED VISIBILITY by compliance design — they are NOT incidents. Anything matching",
        "a baseline is normal operation. Anything outside this set is either new application",
        "behaviour or intrusion.",
        "",
        "## Constants",
        "",
        _block({
            "steady_state_flows_per_minute": baselines.STEADY_STATE_FLOWS_PER_MINUTE,
            "mgt_audit_alert_rate_per_minute": baselines.MGT_AUDIT_ALERT_RATE_PER_MINUTE,
        }),
        "",
        "## Anomalous patterns (NOT in baseline — red flags)",
        "",
        "Flows matching any of these are NEVER seen in production and indicate intrusion:",
        "",
    ]
    for ap in baselines.ANOMALOUS_PATTERNS:
        parts.append(f"- {ap}")
    parts += [
        "",
        _block({"anomalous_patterns": baselines.ANOMALOUS_PATTERNS}),
        "",
        "## Application traffic flows",
        "",
    ]
    for p in baselines.APPLICATION_FLOWS:
        d = p.model_dump()
        d["criticality_to_business"] = p.criticality_to_business.value
        parts += [
            f"### {p.name}",
            "",
            f"`{p.src_ip}` → `{p.dst_ip}:{p.dst_port}/{p.proto}`, "
            f"cadence: {p.cadence}, criticality: **{p.criticality_to_business.value}**",
            "",
            f"{p.production_description}",
            "",
            f"- **Anomaly trigger**: {p.burst_anomaly_threshold}",
            f"- **If disrupted**: {p.if_disrupted}",
            "",
            _block(d),
            "",
        ]
    parts += ["## Management plane flows", ""]
    for p in baselines.MANAGEMENT_FLOWS:
        d = p.model_dump()
        d["criticality_to_business"] = p.criticality_to_business.value
        parts += [
            f"### {p.name}",
            "",
            f"`{p.src_ip}` → `{p.dst_ip}:{p.dst_port}/{p.proto}`, "
            f"cadence: {p.cadence}, criticality: **{p.criticality_to_business.value}**",
            "",
            f"{p.production_description}",
            "",
            f"- **Anomaly trigger**: {p.burst_anomaly_threshold}",
            f"- **If disrupted**: {p.if_disrupted}",
            "",
            _block(d),
            "",
        ]
    (OUT / "baselines.md").write_text("\n".join(parts))
    print(f"  ✓ baselines.md  ({len(baselines.ALL_BASELINES)} baselines, "
          f"{len(baselines.ANOMALOUS_PATTERNS)} anomalous patterns)")


# ─────────────────────────────────────────────────────────────────────────────
# policy-matrix.md
# ─────────────────────────────────────────────────────────────────────────────
def write_policy() -> None:
    parts: list[str] = [
        "# Zone-to-Zone Policy Matrix",
        "",
        "Explicit ALLOW/DENY per directed zone pair. Pairs not listed default to DENY.",
        "Reply traffic of any ALLOW flow is permitted via stateful conntrack.",
        "",
        "| Source ↓ \\ Destination → | WEB | DB | APP | MGT |",
        "|---|---|---|---|---|",
    ]
    zones = ["WEB", "DB", "APP", "MGT"]
    for src in zones:
        row = [f"**{src}**"]
        for dst in zones:
            if src == dst:
                row.append("—")
            else:
                row.append(policy.POLICY_MATRIX.get((src, dst), "DENY"))
        parts.append("| " + " | ".join(row) + " |")
    parts += [
        "",
        "## Canonical data",
        "",
    ]
    # Serialize tuple keys as 2-element lists for YAML
    rules = [
        {"src_zone": s, "dst_zone": d, "verdict": v}
        for (s, d), v in policy.POLICY_MATRIX.items()
    ]
    parts.append(_block({"policy_matrix": rules}))
    parts.append("")
    (OUT / "policy-matrix.md").write_text("\n".join(parts))
    print(f"  ✓ policy-matrix.md  ({len(policy.POLICY_MATRIX)} pairs)")


# ─────────────────────────────────────────────────────────────────────────────
# sids.md
# ─────────────────────────────────────────────────────────────────────────────
def write_sids() -> None:
    parts: list[str] = [
        "# Suricata SID Inventory",
        "",
        "Active Suricata signatures the IDS emits. Each SID maps to MITRE ATT&CK",
        "tactic/technique and a recommended response (DROP src_ip / log_only / escalate).",
        "P-level: 1=critical, 2=high, 3=info-recon, 4=audit (visibility, not incident).",
        "",
    ]
    for sid in sorted(threat_playbook.SID_DETECTIONS.keys()):
        d = threat_playbook.SID_DETECTIONS[sid]
        m = d.model_dump()
        parts += [
            f"## SID {sid} — {d.signature_msg}",
            "",
            f"**Severity P{d.severity_p_level}**  ·  "
            f"**MITRE**: {d.mitre_tactic} / {d.mitre_technique}  ·  "
            f"**Response**: {d.recommended_response}  ·  "
            f"**FP likelihood**: {d.false_positive_likelihood}",
            "",
            f"{d.production_description}",
            "",
            f"**Detection logic**: `{d.detection_logic}`",
            "",
        ]
        if d.false_positive_scenarios:
            parts.append("**False-positive scenarios**:")
            parts.append("")
            for fp in d.false_positive_scenarios:
                parts.append(f"- {fp}")
            parts.append("")
        parts += [_block(m), ""]
    (OUT / "sids.md").write_text("\n".join(parts))
    print(f"  ✓ sids.md  ({len(threat_playbook.SID_DETECTIONS)} SIDs)")


# ─────────────────────────────────────────────────────────────────────────────
# kill-chains.md
# ─────────────────────────────────────────────────────────────────────────────
def write_kill_chains() -> None:
    parts: list[str] = [
        "# Kill Chains",
        "",
        "Multi-stage adversary playbooks the agent uses to correlate single SIDs into",
        "campaign hypotheses. Each chain has stages with expected SIDs, indicators, and",
        "false-positive caveats. `recommended_intervention_point` tells the agent which",
        "stage to break for cheapest containment.",
        "",
    ]
    for kc in threat_playbook.KILL_CHAINS:
        d = kc.model_dump()
        parts += [
            f"## {kc.name}",
            "",
            f"{kc.production_description}",
            "",
            f"- **Typical dwell between stages**: {kc.typical_dwell_between_stages}",
            f"- **Recommended intervention**: {kc.recommended_intervention_point}",
            f"- **Containment**: {kc.containment_strategy}",
            "",
            "**Stages**:",
            "",
        ]
        for st in kc.stages:
            sigs = ", ".join(str(s) for s in st.expected_signals) or "(none)"
            parts.append(
                f"- **Stage {st.stage} ({st.tactic})** — expected signals: {sigs}. "
                f"{st.production_indicators}"
            )
            if st.false_positive_sources:
                fps = "; ".join(st.false_positive_sources)
                parts.append(f"  - *Possible false positives*: {fps}")
        parts += ["", _block(d), ""]
    (OUT / "kill-chains.md").write_text("\n".join(parts))
    print(f"  ✓ kill-chains.md  ({len(threat_playbook.KILL_CHAINS)} kill chains)")


# ─────────────────────────────────────────────────────────────────────────────
# enforcement-plane.md
# ─────────────────────────────────────────────────────────────────────────────
def write_enforcement_plane() -> None:
    parts: list[str] = [
        "# Enforcement Plane Contract",
        "",
        "Procedural knowledge for how the agent talks to Secure Framework. Endpoint contracts,",
        "field naming, gotchas, failure modes, RBAC. Source of truth for *behaviour expectations*",
        "of the SF REST API — not graph data, but knowledge agent must apply when constructing rules.",
        "",
        "## Endpoints in scope",
        "",
    ]
    for ep, desc in enforcement_plane.ENDPOINT_CONTRACTS.items():
        parts.append(f"### `{ep}`")
        parts.append("")
        parts.append(desc)
        parts.append("")
    parts += [
        _block({
            "endpoint_contracts": [
                {"endpoint": ep, "description": desc}
                for ep, desc in enforcement_plane.ENDPOINT_CONTRACTS.items()
            ]
        }),
        "",
        "## Field name mapping",
        "",
        "Field names drift across REST request body, YANG/gNMI notification, and ConfigDB key.",
        "Most-confused fields are flagged ⚠️.",
        "",
    ]
    parts.append(_block({"field_name_mapping": enforcement_plane.FIELD_NAME_MAPPING}))
    parts += [
        "",
        "## Critical gotchas",
        "",
    ]
    for g in enforcement_plane.CRITICAL_GOTCHAS:
        parts.append(f"- {g}")
    parts.append("")
    parts.append(_block({"critical_gotchas": enforcement_plane.CRITICAL_GOTCHAS}))
    parts += [
        "",
        "## Failure modes",
        "",
    ]
    for fm in enforcement_plane.FAILURE_MODES:
        parts += [
            f"### `{fm.name}`",
            "",
            f"- **Trigger**: {fm.trigger}",
            f"- **REST status**: {fm.rest_status}",
            f"- **Body signature**: {fm.body_signature}",
            f"- **State after**: {fm.state}",
            f"- **Agent action**: {fm.agent_action}",
            "",
        ]
    parts.append(_block({
        "failure_modes": [fm.model_dump() for fm in enforcement_plane.FAILURE_MODES]
    }))
    parts += [
        "",
        "## RBAC contract",
        "",
        enforcement_plane.RBAC_CONTRACT.strip(),
        "",
        _block({"rbac_contract": enforcement_plane.RBAC_CONTRACT.strip()}),
        "",
    ]
    (OUT / "enforcement-plane.md").write_text("\n".join(parts))
    print(f"  ✓ enforcement-plane.md  "
          f"({len(enforcement_plane.ENDPOINT_CONTRACTS)} endpoints, "
          f"{len(enforcement_plane.CRITICAL_GOTCHAS)} gotchas, "
          f"{len(enforcement_plane.FAILURE_MODES)} failure modes)")


# ─────────────────────────────────────────────────────────────────────────────
# invariants.md
# ─────────────────────────────────────────────────────────────────────────────
def write_invariants() -> None:
    parts: list[str] = [
        "# Network Invariants (HARD SAFETY)",
        "",
        "**🛑 Critical safety boundary.** These rules override LLM reasoning. The agent MUST",
        "honour them. If a proposed action violates an invariant, the safety layer fails closed",
        "(no enforcement) regardless of LLM confidence or reasoning quality.",
        "",
        "## Never-block CIDRs (whitelist)",
        "",
        "Blocking any of these IPs causes self-DoS, partition, or loss of audit/perception.",
        "Hardcoded floor enforced both in code (`safety/guardrails.py`) and rendered into the",
        "agent prompt (so the LLM understands *why*, not just *that*).",
        "",
    ]
    for cidr in invariants.NEVER_BLOCK_CIDRS:
        rationale = invariants.NEVER_BLOCK_RATIONALE.get(cidr, "(no rationale recorded)")
        parts.append(f"- `{cidr}` — {rationale}")
    parts += [
        "",
        _block({
            "never_block": [
                {"cidr": cidr,
                 "rationale": invariants.NEVER_BLOCK_RATIONALE.get(cidr, "")}
                for cidr in invariants.NEVER_BLOCK_CIDRS
            ]
        }),
        "",
        "## Allowed agent actions",
        "",
        f"Frozen set: **{', '.join(sorted(invariants.ALLOWED_AGENT_ACTIONS))}**. "
        "Agent role can ONLY push DROP rules. ACCEPT/RETURN must escalate to operator (OU=sdnc).",
        "",
        _block({"allowed_agent_actions": sorted(invariants.ALLOWED_AGENT_ACTIONS)}),
        "",
        "## Comment provenance prefixes",
        "",
        "iptables rule comments encode provenance and enforce ownership boundary.",
        "",
    ]
    for prefix in invariants.PROTECTED_COMMENT_PREFIXES:
        parts.append(f"- `{prefix}*` — baseline ZT policy. Agent MUST NOT modify.")
    parts.append(f"- `{invariants.AGENT_COMMENT_PREFIX}*` — agent-owned rules. Agent maintains TTL + DELETE.")
    parts.append("- (no comment) — operator-manual rule. Agent MUST NOT touch without escalation.")
    parts += [
        "",
        _block({
            "protected_comment_prefixes": list(invariants.PROTECTED_COMMENT_PREFIXES),
            "agent_comment_prefix": invariants.AGENT_COMMENT_PREFIX,
        }),
        "",
    ]
    # Priority bounds (read from invariants.py if present)
    pmin = getattr(invariants, "AGENT_PRIORITY_MIN", None)
    pmax = getattr(invariants, "AGENT_PRIORITY_MAX", None)
    if pmin is not None and pmax is not None:
        parts += [
            "## Priority bounds (agent-pushed rules)",
            "",
            f"Agent rules: priority ∈ `[{pmin}, {pmax}]`. iptables `-A FORWARD` (priority ≥ 1000)",
            "lands rule AFTER `nos:zt-default-drop` and is silently ineffective. Use ≤ 100.",
            "",
            _block({"agent_priority_min": pmin, "agent_priority_max": pmax}),
            "",
        ]
    (OUT / "invariants.md").write_text("\n".join(parts))
    print(f"  ✓ invariants.md  "
          f"({len(invariants.NEVER_BLOCK_CIDRS)} never-block CIDRs, "
          f"{len(invariants.ALLOWED_AGENT_ACTIONS)} allowed actions)")


# ─────────────────────────────────────────────────────────────────────────────
# README.md
# ─────────────────────────────────────────────────────────────────────────────
def write_readme() -> None:
    content = """# `knowledge/infra/` — Machine-Parsable Knowledge Base

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
"""
    (OUT / "README.md").write_text(content)
    print("  ✓ README.md")


def main() -> None:
    print(f"Dumping Pydantic constants → {OUT}/")
    write_zones()
    write_assets()
    write_leafs()
    write_baselines()
    write_policy()
    write_sids()
    write_kill_chains()
    write_enforcement_plane()
    write_invariants()
    write_readme()
    print(f"\n✓ Wrote {len(list(OUT.glob('*.md')))} files to {OUT}")


if __name__ == "__main__":
    main()
