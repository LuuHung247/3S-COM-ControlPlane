"""Multi-hop graph analytics over the datacenter knowledge graph. Pure logic, no I/O.

Gives the agent SOC-style network understanding that a one-hop lookup cannot:

  containment_options() — for each candidate DROP scope (flow / pair / host), which
                          legitimate baseline flows would be cut (collateral damage)
                          and which crown-jewel paths stay open to the attacker.
  attack_surface()      — from a (possibly compromised) source, next hops and shortest
                          paths to crown-jewel assets over policy-permitted edges.
  pivot_chain()         — whether the source was itself the target of an earlier alert
                          (lateral pivot), the upstream root cause, and fan-out breadth.

All results are deterministic functions of the knowledge base (assets, baselines,
8x8 policy matrix) plus the recent alert window, so they are reproducible and safe to
show the LLM: they inform the decision but never authorize enforcement.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from typing import Any

from . import baselines, policy, system_model
from .topology import ip_to_zone

_CRIT_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}
MAX_HOPS = 3


# ── Graph construction ───────────────────────────────────────────────────────
def _bare(ip: str) -> str:
    return (ip or "").split("/")[0]


def _zone_asset(zone: str | None) -> system_model.Asset | None:
    for a in system_model.ASSETS.values():
        if a.zone == zone:
            return a
    return None


def resolve_asset(ip: str) -> system_model.Asset | None:
    """Exact asset, else the zone's primary asset (secondary hosts share its role)."""
    return system_model.get_asset(_bare(ip)) or _zone_asset(ip_to_zone(_bare(ip)))


def is_crown_jewel(asset: system_model.Asset | None) -> bool:
    return bool(asset) and asset.criticality.value == "critical" and \
        asset.data_classification.value in ("confidential", "restricted")


def _zone_reach(src_zone: str) -> list[str]:
    return [d for (s, d), v in policy.POLICY_MATRIX.items() if s == src_zone and v == "ALLOW"]


def _flows_from(ip: str) -> list[baselines.TrafficPattern]:
    return [b for b in baselines.ALL_BASELINES if b.src_ip == _bare(ip)]


def _flows_into(ip: str) -> list[baselines.TrafficPattern]:
    """Baseline flows whose responder is ip — including fan-out (scrape/audit) flows
    whose source zone is permitted to reach ip's zone."""
    bare, zone = _bare(ip), ip_to_zone(_bare(ip))
    out = []
    for b in baselines.ALL_BASELINES:
        if b.dst_ip == bare:
            out.append(b)
        elif b.dst_ip in ("", "rotating") and zone and zone in _zone_reach(b.src_zone):
            out.append(b)
    return out


def _flow_desc(b: baselines.TrafficPattern) -> dict[str, Any]:
    return {"name": b.name, "src": b.src_ip, "dst": b.dst_ip or f"{b.dst_zone or 'fan-out'}",
            "port": b.dst_port, "criticality": b.criticality_to_business.value}


# ── 1. Containment options ───────────────────────────────────────────────────
def containment_options(src_ip: str, dst_ip: str = "", dst_port: int = 0) -> list[dict[str, Any]]:
    """Collateral damage per DROP scope. A source-side DROP also drops the source's
    replies, so host scope cuts the source's inbound services as well."""
    src, dst = _bare(src_ip), _bare(dst_ip)
    out_flows = _flows_from(src)
    scopes = []

    def summarize(scope: str, rule: str, cut: list[baselines.TrafficPattern], blocked_dst: set[str]):
        surface = attack_surface(src, exclude_dsts=blocked_dst)
        scopes.append({
            "scope": scope,
            "rule": rule,
            "legit_flows_cut": [_flow_desc(b) for b in cut],
            "n_cut": len(cut),
            "max_cut_criticality": max((b.criticality_to_business.value for b in cut),
                                       key=lambda c: _CRIT_RANK.get(c, 0), default="none"),
            "crown_jewels_still_reachable": [p["target"] for p in surface["crown_jewel_paths"]],
        })

    if dst:
        summarize("flow", f"DROP {src}/32 -> {dst}/32:{dst_port}",
                  [b for b in out_flows if b.dst_ip == dst and b.dst_port == dst_port], set())
        summarize("pair", f"DROP {src}/32 -> {dst}/32 any port",
                  [b for b in out_flows if b.dst_ip == dst], {dst})
    host_cut = out_flows + [b for b in _flows_into(src) if b not in out_flows]
    summarize("host", f"DROP {src}/32 -> any", host_cut, {"*"})
    return scopes


# ── 2. Attack surface ────────────────────────────────────────────────────────
def attack_surface(src_ip: str, exclude_dsts: set[str] | None = None) -> dict[str, Any]:
    """BFS over policy-permitted zone edges from the source's zone. exclude_dsts
    removes first-hop destinations already blocked ('*' = source fully isolated)."""
    exclude = exclude_dsts or set()
    src_zone = ip_to_zone(_bare(src_ip))
    if src_zone is None or "*" in exclude:
        return {"src_zone": src_zone, "next_hops": [], "crown_jewel_paths": []}
    excluded_zones = {ip_to_zone(d) for d in exclude}
    next_hops = []
    for z in _zone_reach(src_zone):
        a = _zone_asset(z)
        if a and z not in excluded_zones:
            ports = sorted({b.dst_port for b in _flows_from(src_ip) if b.dst_ip == a.ip} or
                           {s.port for s in a.services if s.port != 22})
            next_hops.append({"zone": z, "asset": a.hostname, "ip": a.ip, "ports": ports,
                              "criticality": a.criticality.value, "crown_jewel": is_crown_jewel(a)})

    parent: dict[str, str | None] = {src_zone: None}
    q, paths = deque([(src_zone, 0)]), []
    while q:
        z, d = q.popleft()
        if d >= MAX_HOPS:
            continue
        for nz in _zone_reach(z):
            if nz in parent or (d == 0 and nz in excluded_zones):
                continue
            parent[nz] = z
            q.append((nz, d + 1))
            a = _zone_asset(nz)
            if is_crown_jewel(a):
                hop, chain = nz, []
                while hop is not None:
                    chain.append(hop)
                    hop = parent[hop]
                paths.append({"target": f"{a.hostname} ({a.zone})", "hops": d + 1,
                              "path": " -> ".join(reversed(chain))})
    paths.sort(key=lambda p: p["hops"])
    return {"src_zone": src_zone, "next_hops": next_hops, "crown_jewel_paths": paths}


# ── 3. Pivot chain / root cause ──────────────────────────────────────────────
def _ts(a: dict[str, Any]) -> float:
    try:
        return datetime.fromisoformat(str(a.get("timestamp", "")).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def pivot_chain(src_ip: str, recent_alerts: list[dict[str, Any]], window_s: int = 900,
                now: float | None = None) -> dict[str, Any]:
    """recent_alerts: raw Suricata alerts (any source) from the recent window."""
    now = now or datetime.now(timezone.utc).timestamp()
    alerts = [a for a in recent_alerts if now - _ts(a) <= window_s]
    src = _bare(src_ip)
    fan_out = sorted({_bare(a.get("dest_ip", "")) for a in alerts if _bare(a.get("src_ip", "")) == src})

    chain, cur, seen = [], src, {src}
    while True:
        first_seen_as_src = min((_ts(a) for a in alerts if _bare(a.get("src_ip", "")) == cur), default=now)
        upstream = [a for a in alerts if _bare(a.get("dest_ip", "")) == cur
                    and _bare(a.get("src_ip", "")) not in seen and _ts(a) <= first_seen_as_src]
        if not upstream:
            break
        u = min(upstream, key=_ts)
        uip = _bare(u.get("src_ip", ""))
        chain.append({"from": uip, "to": cur, "sid": (u.get("alert") or {}).get("signature_id"),
                      "at": u.get("timestamp", "")})
        seen.add(uip)
        cur = uip
    return {"is_pivot": bool(chain), "root_cause_src": cur if chain else src,
            "chain": list(reversed(chain)), "distinct_targets_from_src": fan_out}


# ── Rendering ────────────────────────────────────────────────────────────────
def render_for_alert(src_ip: str, dst_ip: str, dst_port: int,
                     recent_alerts: list[dict[str, Any]] | None = None) -> str:
    opts = containment_options(src_ip, dst_ip, dst_port)
    surf = attack_surface(src_ip)
    piv = pivot_chain(src_ip, recent_alerts or [])
    lines = ["### Graph analytics (multi-hop, deterministic)",
             "Containment options — legitimate baseline flows each DROP scope would cut:"]
    for o in opts:
        cut = ", ".join(f"{f['name']}[{f['criticality']}]" for f in o["legit_flows_cut"]) or "none"
        reach = ", ".join(o["crown_jewels_still_reachable"]) or "none"
        lines.append(f"- {o['scope']}: `{o['rule']}` → cuts {o['n_cut']} ({cut}); "
                     f"crown jewels still reachable by source: {reach}")
    hops = ", ".join(f"{h['asset']}({h['zone']}:{'/'.join(map(str, h['ports']))})"
                     f"{'*' if h['crown_jewel'] else ''}" for h in surf["next_hops"]) or "none"
    lines.append(f"Attack surface from {surf['src_zone']}: permitted next hops {hops} (* = crown jewel)")
    for p in surf["crown_jewel_paths"][:3]:
        lines.append(f"- path to {p['target']}: {p['path']} ({p['hops']} hop{'s' if p['hops'] > 1 else ''})")
    if piv["is_pivot"]:
        steps = " ; ".join(f"{c['from']}→{c['to']} (SID {c['sid']})" for c in piv["chain"])
        lines.append(f"Pivot detected: source was previously targeted — chain {steps}; "
                     f"root cause {piv['root_cause_src']}")
    else:
        lines.append("Pivot: source was not the target of any alert in the last 15 min")
    lines.append(f"Distinct targets alerted from this source (15 min): "
                 f"{len(piv['distinct_targets_from_src'])} {piv['distinct_targets_from_src']}")
    sig = escalation_signals(src_ip, dst_ip, dst_port, recent_alerts or [], opts, piv)
    lines.append("Escalation signals: " + ", ".join(f"{k}={v}" for k, v in sig.items()))
    return "\n".join(lines)


def escalation_signals(src_ip: str, dst_ip: str, dst_port: int, recent_alerts: list[dict[str, Any]],
                       opts: list[dict[str, Any]] | None = None,
                       piv: dict[str, Any] | None = None) -> dict[str, Any]:
    """Facts the containment-scope judgement rests on, summarised in one place."""
    opts = opts if opts is not None else containment_options(src_ip, dst_ip, dst_port)
    piv = piv if piv is not None else pivot_chain(src_ip, recent_alerts)
    src, dst = _bare(src_ip), _bare(dst_ip)
    ports = {int(a.get("dest_port") or 0) for a in recent_alerts
             if _bare(a.get("src_ip", "")) == src and _bare(a.get("dest_ip", "")) == dst}
    flow = next((o for o in opts if o["scope"] == "flow"), None)
    return {
        "pivot": "yes" if piv["is_pivot"] else "no",
        "root_cause": piv["root_cause_src"],
        "distinct_targets": len(piv["distinct_targets_from_src"]),
        "ports_on_this_target": len(ports | {int(dst_port or 0)}),
        "crown_jewel_path_open_under_flow_scope":
            "yes" if flow and flow["crown_jewels_still_reachable"] else "no",
    }
