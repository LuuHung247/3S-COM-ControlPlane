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
# Zone catalog — 4 trust zones
# ─────────────────────────────────────────────────────────────────────────────
ZONES: dict[str, Zone] = {
    "WEB": Zone(
        name="WEB",
        cidr="10.1.100.0/24",
        leaf="LEAF-1",
        vlan=100,
        svi_gateway="10.1.100.1",
        purpose="Public-facing web tier serving HTTP for end users (north-south ingress)",
        trust_level=TrustLevel.UNTRUSTED,
        criticality=Criticality.HIGH,
    ),
    "DB": Zone(
        name="DB",
        cidr="10.1.200.0/24",
        leaf="LEAF-1",
        vlan=200,
        svi_gateway="10.1.200.1",
        purpose="Database tier holding persistent application state and sensitive data",
        trust_level=TrustLevel.CROWN_JEWEL,
        criticality=Criticality.CRITICAL,
    ),
    "APP": Zone(
        name="APP",
        cidr="10.2.100.0/24",
        leaf="LEAF-2",
        vlan=100,
        svi_gateway="10.2.100.1",
        purpose="Business-logic / application tier mediating between WEB and DB",
        trust_level=TrustLevel.TRUSTED_INTERNAL,
        criticality=Criticality.HIGH,
    ),
    "MGT": Zone(
        name="MGT",
        cidr="10.2.50.0/24",
        leaf="LEAF-2",
        vlan=300,
        svi_gateway="10.2.50.1",
        purpose="Management plane for monitoring, audit, and configuration. Universal access by compliance design.",
        trust_level=TrustLevel.PRIVILEGED,
        criticality=Criticality.CRITICAL,
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# Asset catalog — 4 workload hosts (one per zone)
# ─────────────────────────────────────────────────────────────────────────────
ASSETS: dict[str, Asset] = {
    "10.1.100.10": Asset(
        ip="10.1.100.10",
        hostname="web-01",
        zone="WEB",
        tier="presentation tier",
        role="Public-facing HTTP frontend serving end-user requests",
        criticality=Criticality.HIGH,
        data_classification=DataClassification.PUBLIC,
        services=[
            Service(port=80, proto="tcp", name="http", facing="external",
                    purpose="Serves HTTP banner content to external users — north-south ingress entry point"),
            Service(port=22, proto="tcp", name="sshd", facing="internal-mgt-only",
                    purpose="Operational SSH access restricted to management plane"),
        ],
        expected_inbound_sources=["external", "MGT"],
        expected_outbound_destinations=["10.2.100.10:8080 (APP tier API)"],
        if_compromised_impact=(
            "Adversary gains foothold on Internet-exposed tier. Pivots toward APP tier through "
            "legitimate WEB→APP path, or attempts direct DB access bypassing application controls."
        ),
        if_blocked_impact=(
            "End-user-facing HTTP service goes dark. Outbound proxy to APP tier breaks. "
            "User experience fully degraded."
        ),
        owner_team="platform",
    ),
    "10.1.200.10": Asset(
        ip="10.1.200.10",
        hostname="db-01",
        zone="DB",
        tier="data tier",
        role="SQL backend serving OLTP transactions for the application tier",
        criticality=Criticality.CRITICAL,
        data_classification=DataClassification.CONFIDENTIAL,
        services=[
            Service(port=5432, proto="tcp", name="postgresql-wire", facing="internal-app-only",
                    purpose="Serves SQL transactions (SELECT/INSERT/UPDATE) issued by APP tier"),
            Service(port=22, proto="tcp", name="sshd", facing="internal-mgt-only",
                    purpose="Operational SSH restricted to management plane for compliance audit"),
        ],
        expected_inbound_sources=["APP", "MGT"],
        expected_outbound_destinations=[],   # Crown jewel — never initiates outbound
        if_compromised_impact=(
            "Crown-jewel breach. Adversary has direct read/write to persistent business state. "
            "Likely follow-up: data exfiltration over outbound channel (C2 beacon, DNS tunnel, "
            "or SSH covert tunnel)."
        ),
        if_blocked_impact=(
            "Full application outage. APP tier loses transactional backend. All user-facing "
            "operations requiring DB read/write fail. Highest-cost block target."
        ),
        owner_team="data",
    ),
    "10.2.100.10": Asset(
        ip="10.2.100.10",
        hostname="app-01",
        zone="APP",
        tier="application tier",
        role="Business logic tier bridging WEB requests to DB transactions",
        criticality=Criticality.HIGH,
        data_classification=DataClassification.INTERNAL,
        services=[
            Service(port=8080, proto="tcp", name="http-api", facing="any",
                    purpose="Application HTTP API consumed by WEB tier proxy and MGT health probes"),
            Service(port=22, proto="tcp", name="sshd", facing="internal-mgt-only",
                    purpose="Operational SSH for compliance audit and log retrieval"),
        ],
        expected_inbound_sources=["WEB", "MGT"],
        expected_outbound_destinations=["10.1.200.10:5432 (DB tier OLTP)"],
        if_compromised_impact=(
            "Adversary on application tier has legitimate path to DB. Risk: SQL exfiltration "
            "via application-mediated channel, or pivot to MGT zone for credential abuse."
        ),
        if_blocked_impact=(
            "Application logic tier offline. WEB requests cannot reach DB. End-user operations "
            "fail. Cascade outage to presentation tier."
        ),
        owner_team="platform",
    ),
    "10.2.50.10": Asset(
        ip="10.2.50.10",
        hostname="mgt-01",
        zone="MGT",
        tier="management plane",
        role="Operational host running compliance audit, health scrape, log collection",
        criticality=Criticality.CRITICAL,
        data_classification=DataClassification.RESTRICTED,
        services=[
            Service(port=22, proto="tcp", name="sshd", facing="internal-mgt-only",
                    purpose="Operational entry point — only listening service; no application workload"),
        ],
        expected_inbound_sources=["MGT"],   # Only self / other MGT hosts (no others currently)
        expected_outbound_destinations=[
            "10.1.100.10:80 (WEB scrape)",
            "10.1.100.10:22 (WEB audit)",
            "10.2.100.10:8080 (APP scrape)",
            "10.2.100.10:22 (APP audit + logpull)",
            "10.1.200.10:5432 (DB scrape)",
            "10.1.200.10:22 (DB audit)",
        ],
        if_compromised_impact=(
            "TOTAL SYSTEM COMPROMISE. Management plane has universal access by design. "
            "Adversary on MGT can reach every zone, every host, with legitimate credentials. "
            "Lateral movement is unconstrained."
        ),
        if_blocked_impact=(
            "Loss of compliance audit, health monitoring, log collection. Operational visibility "
            "blind. Agent itself loses ability to verify network state from MGT vantage. "
            "MUST NEVER be blocked by automated agent."
        ),
        owner_team="ops",
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# Leaf catalog — enforcement points
# ─────────────────────────────────────────────────────────────────────────────
LEAFS: dict[str, Leaf] = {
    "LEAF-1": Leaf(
        name="LEAF-1",
        mgmt_ip="192.168.122.20",
        zones=["WEB", "DB"],
        role="Enforcement point for WEB and DB zones (intra-leaf and cross-leaf rules)",
    ),
    "LEAF-2": Leaf(
        name="LEAF-2",
        mgmt_ip="192.168.122.21",
        zones=["APP", "MGT"],
        role="Enforcement point for APP and MGT zones",
    ),
}


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
