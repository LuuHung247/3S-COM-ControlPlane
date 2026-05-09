"""Datacenter system model — assets, criticality, services, blast radius.

This is the agent's mental model of WHAT the datacenter IS today. Production language —
no test/lab/cron terminology. Every field describes a real production datacenter.

Source of truth: knowledge/01-DATAPLANE.md (mirrored at docs/DATAPLANE.md for humans).
"""
from enum import Enum
from pydantic import BaseModel


class Criticality(str, Enum):
    """Asset criticality reflecting blast radius if compromised or blocked."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class TrustLevel(str, Enum):
    UNTRUSTED = "untrusted"          # Internet-facing, assume compromised
    TRUSTED_INTERNAL = "trusted-internal"
    CROWN_JEWEL = "crown-jewel"      # Holds sensitive state, no outbound
    PRIVILEGED = "privileged"        # Universal access by design


class Service(BaseModel):
    port: int
    proto: str                        # "tcp", "udp", "icmp"
    name: str                         # "postgresql", "sshd"
    facing: str                       # "internal-app-only", "internal-mgt-only", "external", "any"
    purpose: str                      # production-language description


class Zone(BaseModel):
    name: str
    cidr: str
    leaf: str                         # "LEAF-1" or "LEAF-2"
    vlan: int
    svi_gateway: str
    purpose: str
    trust_level: TrustLevel
    criticality: Criticality


class Asset(BaseModel):
    """A single workload host. Each zone hosts exactly one asset."""
    ip: str
    hostname: str
    zone: str                         # Zone name
    tier: str                         # "presentation tier", "application tier", "data tier", "management plane"
    role: str                         # one-sentence production role
    criticality: Criticality
    data_classification: DataClassification
    services: list[Service]
    expected_inbound_sources: list[str]       # zones or specific IPs
    expected_outbound_destinations: list[str] # zones or specific IPs/ports
    if_compromised_impact: str        # blast radius prose
    if_blocked_impact: str            # what business function breaks if DROP this IP
    owner_team: str


class Leaf(BaseModel):
    name: str
    mgmt_ip: str
    zones: list[str]
    role: str


# ─────────────────────────────────────────────────────────────────────────────
# Zone / Asset / Leaf catalogs — populated from knowledge/infra/*.md at import.
#
# Authoring source: knowledge/infra/{zones,assets,leafs}.md
# Bootstrap path:   .md → knowledge_parser → these dicts (at import time)
# Runtime path:     replaced in-place at app startup by Neo4j read (see main.py
#                   lifespan → storage.neo4j_reader.read_all). Neo4j is the
#                   durable source; .md is the authoring layer; this in-RAM
#                   dict is the read cache.
# ─────────────────────────────────────────────────────────────────────────────
from . import knowledge_parser as _kp

ZONES: dict[str, Zone] = _kp.parse_zones()
ASSETS: dict[str, Asset] = _kp.parse_assets()
LEAFS: dict[str, Leaf] = _kp.parse_leafs()


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def get_asset(ip_or_cidr: str) -> Asset | None:
    """Lookup asset by exact IP or single-host CIDR (e.g. '10.1.100.10/32')."""
    bare = ip_or_cidr.split("/")[0]
    return ASSETS.get(bare)


def get_zone(zone_name: str) -> Zone | None:
    return ZONES.get(zone_name)


def _render_zone(z: Zone) -> str:
    return (
        f"- **{z.name}** ({z.cidr}, VLAN {z.vlan}, SVI {z.svi_gateway}, on {z.leaf}) — "
        f"trust={z.trust_level.value}, criticality={z.criticality.value}. {z.purpose}"
    )


def _render_asset(a: Asset) -> str:
    services_str = ", ".join(f"{s.port}/{s.proto} {s.name} ({s.facing})" for s in a.services)
    return (
        f"- **{a.hostname}** `{a.ip}` (zone {a.zone}, {a.tier}) — "
        f"criticality={a.criticality.value}, data={a.data_classification.value}\n"
        f"  - Role: {a.role}\n"
        f"  - Services: {services_str}\n"
        f"  - Expected inbound: {', '.join(a.expected_inbound_sources) or '(none)'}\n"
        f"  - Expected outbound: {', '.join(a.expected_outbound_destinations) or '(none — does not initiate outbound)'}\n"
        f"  - If compromised: {a.if_compromised_impact}\n"
        f"  - If blocked: {a.if_blocked_impact}"
    )


def _render_leaf(l: Leaf) -> str:
    return f"- **{l.name}** mgmt {l.mgmt_ip} — manages zones {l.zones}. {l.role}"


def render_for_prompt() -> str:
    """Render FULL system model — used for startup verification and KG visualization."""
    parts: list[str] = ["## DATACENTER SYSTEM MODEL\n", "### Trust Zones (4)\n"]
    parts.extend(_render_zone(z) for z in ZONES.values())
    parts.append("\n### Workload Assets (4 hosts, one per zone)\n")
    parts.extend(_render_asset(a) for a in ASSETS.values())
    parts.append("\n### Enforcement Leafs (2)\n")
    parts.extend(_render_leaf(l) for l in LEAFS.values())
    return "\n".join(parts)


def render_for_alert(src_ip: str, dst_ip: str = "") -> str:
    """Render ONLY zones, assets, leafs involved in this specific alert.
    Reduces prompt size by ~60% vs full render.
    """
    bare_src = src_ip.split("/")[0] if src_ip else ""
    bare_dst = dst_ip.split("/")[0] if dst_ip else ""

    src_asset = ASSETS.get(bare_src)
    dst_asset = ASSETS.get(bare_dst)

    relevant_zones = set()
    if src_asset:
        relevant_zones.add(src_asset.zone)
    if dst_asset:
        relevant_zones.add(dst_asset.zone)
    # Always include MGT zone — agent must know it exists for never-block reasoning
    relevant_zones.add("MGT")

    relevant_leafs = set()
    for zname in relevant_zones:
        z = ZONES.get(zname)
        if z:
            relevant_leafs.add(z.leaf)

    parts: list[str] = ["## SYSTEM MODEL (alert-specific slice)\n"]

    parts.append("### Zones involved\n")
    for zname in relevant_zones:
        z = ZONES.get(zname)
        if z:
            parts.append(_render_zone(z))

    parts.append("\n### Hosts involved\n")
    if src_asset:
        parts.append(_render_asset(src_asset))
    if dst_asset and dst_asset is not src_asset:
        parts.append(_render_asset(dst_asset))
    if not src_asset and not dst_asset:
        parts.append("(neither src nor dst is a known workload host)")

    parts.append("\n### Enforcement leafs\n")
    for lname in relevant_leafs:
        l = LEAFS.get(lname)
        if l:
            parts.append(_render_leaf(l))

    return "\n".join(parts)
