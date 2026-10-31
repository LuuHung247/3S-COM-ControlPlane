"""NetworkX-based knowledge graph for network topology. No I/O — pure domain logic."""
import ipaddress
import networkx as nx

# V2 topology — 8-zone / 4-leaf / 2-spine Clos (mirrors knowledge_v2/infra/{zones,assets,leafs}.md).
# Hardcoded here for the pure-domain routing helpers (ip_to_zone/ip_to_leaf); the
# authored source of truth is knowledge_v2 → Neo4j → system_model. Keep in sync.
ZONES: dict[str, dict] = {
    "WEB":          {"cidr": "10.1.100.0/24", "leaf": "LEAF-1", "vlan": 100, "svi": "10.1.100.1"},
    "DB-OLTP":      {"cidr": "10.1.200.0/24", "leaf": "LEAF-1", "vlan": 200, "svi": "10.1.200.1"},
    "APP-CORE":     {"cidr": "10.2.100.0/24", "leaf": "LEAF-2", "vlan": 100, "svi": "10.2.100.1"},
    "MGT":          {"cidr": "10.2.50.0/24",  "leaf": "LEAF-2", "vlan": 300, "svi": "10.2.50.1"},
    "APP-GW":       {"cidr": "10.3.100.0/24", "leaf": "LEAF-3", "vlan": 100, "svi": "10.3.100.1"},
    "DB-ANALYTICS": {"cidr": "10.3.200.0/24", "leaf": "LEAF-3", "vlan": 200, "svi": "10.3.200.1"},
    "WORKER":       {"cidr": "10.4.100.0/24", "leaf": "LEAF-4", "vlan": 100, "svi": "10.4.100.1"},
    "MONITORING":   {"cidr": "10.4.200.0/24", "leaf": "LEAF-4", "vlan": 200, "svi": "10.4.200.1"},
}

HOSTS: dict[str, dict] = {
    "web-01":          {"ip": "10.1.100.10", "zone": "WEB"},
    "db-oltp-01":      {"ip": "10.1.200.10", "zone": "DB-OLTP"},
    "app-core-01":     {"ip": "10.2.100.10", "zone": "APP-CORE"},
    "mgt-01":          {"ip": "10.2.50.10",  "zone": "MGT"},
    "app-gw-01":       {"ip": "10.3.100.10", "zone": "APP-GW"},
    "db-analytics-01": {"ip": "10.3.200.10", "zone": "DB-ANALYTICS"},
    "worker-01":       {"ip": "10.4.100.10", "zone": "WORKER"},
    "monitoring-01":   {"ip": "10.4.200.10", "zone": "MONITORING"},
}

LEAFS: dict[str, dict] = {
    "LEAF-1": {"ssh_host": "192.168.122.20", "zones": ["WEB", "DB-OLTP"]},
    "LEAF-2": {"ssh_host": "192.168.122.21", "zones": ["APP-CORE", "MGT"]},
    "LEAF-3": {"ssh_host": "192.168.122.22", "zones": ["APP-GW", "DB-ANALYTICS"]},
    "LEAF-4": {"ssh_host": "192.168.122.23", "zones": ["WORKER", "MONITORING"]},
}


def build_graph() -> nx.DiGraph:
    G = nx.DiGraph()
    for zone, attrs in ZONES.items():
        G.add_node(zone, type="zone", **attrs)
    for host, attrs in HOSTS.items():
        G.add_node(host, type="host", **attrs)
        G.add_edge(host, attrs["zone"], rel="belongs_to")
    for leaf, attrs in LEAFS.items():
        G.add_node(leaf, type="leaf", **attrs)
        for zone in attrs["zones"]:
            G.add_edge(leaf, zone, rel="enforces")
    return G


_GRAPH: nx.DiGraph | None = None


def get_graph() -> nx.DiGraph:
    global _GRAPH
    if _GRAPH is None:
        _GRAPH = build_graph()
    return _GRAPH


def ip_to_zone(ip: str) -> str | None:
    """Return zone name for a given IP, or None if not in any zone."""
    bare = ip.split("/")[0]
    try:
        addr = ipaddress.ip_address(bare)
    except ValueError:
        return None
    for zone, attrs in ZONES.items():
        if addr in ipaddress.ip_network(attrs["cidr"]):
            return zone
    return None


def ip_to_leaf(ip: str) -> str | None:
    zone = ip_to_zone(ip)
    if zone is None:
        return None
    for leaf, attrs in LEAFS.items():
        if zone in attrs["zones"]:
            return leaf
    return None


def zone_svis() -> list[str]:
    return [attrs["svi"] for attrs in ZONES.values()]
