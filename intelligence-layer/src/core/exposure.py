"""Lateral-movement exposure of a microsegmentation configuration. Pure logic, no I/O.

The fabric is modelled as a directed service graph: an edge (src_zone, dst_zone, port)
exists when the policy matrix permits the zone pair and the destination zone's asset
exposes that service port. Exposure is then measured by what an adversary who has
compromised one zone can still reach over permitted edges.

Metrics (following the microsegmentation evaluation framework of Basta et al.):
  ENICE  — number of ordered zone pairs reachable over permitted edges (attack surface).
  CJR    — reachable (source, crown-jewel) pairs; crown jewels are critical assets
           holding confidential/restricted data.
  MPL    — mean shortest path length, in hops, from a source to a reachable crown jewel;
           longer paths mean more enforcement points an adversary must cross.

A runtime containment rule is applied to the graph by removing the edges it blocks, so
the residual exposure of a contained incident is measured on the same footing as the
static configuration. `collateral` counts the legitimate baseline flows those same
removed edges carry, which is the price paid for the reduction.
"""
from __future__ import annotations

from collections import deque
from typing import Any, Iterable

from . import baselines, policy, system_model
from .graph_analytics import is_crown_jewel, resolve_asset
from .topology import ip_to_zone

Edge = tuple[str, str, int]
MAX_HOPS = 8


def zones() -> list[str]:
    return sorted({z for pair in policy.POLICY_MATRIX for z in pair})


def crown_jewel_zones() -> set[str]:
    return {a.zone for a in system_model.ASSETS.values() if is_crown_jewel(a)}


def _ports_of(zone: str) -> set[int]:
    return {s.port for a in system_model.ASSETS.values() if a.zone == zone for s in a.services}


def service_edges(allow_pairs: Iterable[tuple[str, str]] | None = None) -> set[Edge]:
    """Permitted (src_zone, dst_zone, port) edges. Defaults to the deployed matrix."""
    pairs = allow_pairs if allow_pairs is not None else [
        (s, d) for (s, d), v in policy.POLICY_MATRIX.items() if v == "ALLOW" and s != d
    ]
    return {(s, d, p) for s, d in pairs if s != d for p in _ports_of(d)}


def flat_edges() -> set[Edge]:
    """The no-segmentation reference: every zone pair permitted."""
    zs = zones()
    return service_edges([(s, d) for s in zs for d in zs if s != d])


def reachable(edges: set[Edge], src: str) -> dict[str, int]:
    """Zones reachable from src over `edges`, mapped to shortest hop count."""
    adj: dict[str, set[str]] = {}
    for s, d, _ in edges:
        adj.setdefault(s, set()).add(d)
    hops = {src: 0}
    q = deque([src])
    while q:
        z = q.popleft()
        if hops[z] >= MAX_HOPS:
            continue
        for nxt in adj.get(z, ()):
            if nxt not in hops:
                hops[nxt] = hops[z] + 1
                q.append(nxt)
    hops.pop(src, None)
    return hops


def exposure_from(edges: set[Edge], src: str) -> dict[str, Any]:
    """Exposure of one source at two granularities.

    Zone level answers "which zones can still be reached", i.e. lateral reach. Service
    level answers "how many permitted service edges does this source still have", which
    is what a flow-scope rule reduces: it closes one service without closing the zone.
    """
    hops = reachable(edges, src)
    cj = {z: h for z, h in hops.items() if z in crown_jewel_zones()}
    services = {e for e in edges if e[0] == src}
    cj_services = {e for e in services if e[1] in crown_jewel_zones()}
    return {"src_zone": src, "reachable_zones": sorted(hops), "n_reachable": len(hops),
            "crown_jewels_reachable": sorted(cj), "n_crown_jewels": len(cj),
            "min_hops_to_crown_jewel": min(cj.values()) if cj else None,
            "n_services": len(services), "n_crown_jewel_services": len(cj_services)}


def exposure_metrics(edges: set[Edge]) -> dict[str, Any]:
    """Fabric-wide ENICE / CJR / MPL over every source zone."""
    enice = cjr = 0
    paths: list[int] = []
    for z in zones():
        e = exposure_from(edges, z)
        enice += e["n_reachable"]
        cjr += e["n_crown_jewels"]
        hops = reachable(edges, z)
        paths += [h for t, h in hops.items() if t in crown_jewel_zones()]
    return {"n_edges": len(edges), "ENICE": enice, "CJR": cjr,
            "MPL": round(sum(paths) / len(paths), 3) if paths else None}


# ── Runtime containment ──────────────────────────────────────────────────────
def scope_of(src_ip: str, dst_ip: str, dst_port: int) -> str:
    """Containment scope implied by a rule tuple (empty dst = host, no port = pair)."""
    if not (dst_ip or "").split("/")[0]:
        return "host"
    return "pair" if not dst_port else "flow"


def blocked_edges(edges: set[Edge], src_zone: str, scope: str,
                  dst_zone: str | None = None, dst_port: int = 0) -> set[Edge]:
    if scope == "host":
        return {e for e in edges if e[0] == src_zone}
    if scope == "pair":
        return {e for e in edges if e[0] == src_zone and e[1] == dst_zone}
    return {e for e in edges if e == (src_zone, dst_zone, dst_port)}


def collateral(removed: set[Edge]) -> list[dict[str, Any]]:
    """Legitimate baseline flows carried by the removed edges."""
    out = []
    for b in baselines.ALL_BASELINES:
        bz = ip_to_zone(b.src_ip)
        dz = ip_to_zone(b.dst_ip) if b.dst_ip not in ("", "rotating") else None
        for s, d, p in removed:
            if bz == s and int(b.dst_port or 0) == p and (dz == d or dz is None):
                out.append({"name": b.name, "edge": f"{s}->{d}:{p}",
                            "criticality": b.criticality_to_business.value})
                break
    return out


def containment_effect(src_ip: str, dst_ip: str = "", dst_port: int = 0,
                       scope: str | None = None) -> dict[str, Any]:
    """Exposure of the compromised source before vs after one containment rule.

    Reported per incident so that configurations which contain more and configurations
    which disrupt less can be compared on the same two axes.
    """
    src_zone = ip_to_zone((src_ip or "").split("/")[0])
    dst_zone = ip_to_zone((dst_ip or "").split("/")[0]) if dst_ip else None
    scope = scope or scope_of(src_ip, dst_ip, dst_port)
    base = service_edges()
    if src_zone is None:
        return {"src_zone": None, "scope": scope, "error": "source outside fabric zones"}
    removed = blocked_edges(base, src_zone, scope, dst_zone, dst_port)
    before = exposure_from(base, src_zone)
    after = exposure_from(base - removed, src_zone)
    cut = collateral(removed)
    return {
        "src_zone": src_zone, "dst_zone": dst_zone, "scope": scope,
        "edges_removed": len(removed),
        "zones_reachable_before": before["n_reachable"],
        "zones_reachable_after": after["n_reachable"],
        "crown_jewels_before": before["n_crown_jewels"],
        "crown_jewels_after": after["n_crown_jewels"],
        "crown_jewel_contained": before["n_crown_jewels"] > 0 and after["n_crown_jewels"] == 0,
        "exposure_reduction": before["n_reachable"] - after["n_reachable"],
        "services_before": before["n_services"], "services_after": after["n_services"],
        "service_reduction": before["n_services"] - after["n_services"],
        "crown_jewel_services_before": before["n_crown_jewel_services"],
        "crown_jewel_services_after": after["n_crown_jewel_services"],
        "observed_path_blocked": (src_zone, dst_zone, int(dst_port or 0)) in removed
                                 or scope in ("host", "pair"),
        "legit_flows_cut": len(cut), "legit_flows": cut,
        "max_cut_criticality": max((c["criticality"] for c in cut),
                                   key=lambda c: {"critical": 3, "high": 2, "medium": 1, "low": 0}.get(c, 0),
                                   default="none"),
    }


def configuration_table() -> dict[str, dict[str, Any]]:
    """Static reference configurations: no segmentation vs the deployed matrix."""
    return {"flat": exposure_metrics(flat_edges()),
            "static_microsegmentation": exposure_metrics(service_edges())}
