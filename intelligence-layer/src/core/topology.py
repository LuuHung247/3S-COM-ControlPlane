"""NetworkX-based knowledge graph for network topology. No I/O — pure domain logic."""
import ipaddress
import networkx as nx

ZONES: dict[str, dict] = {
    "WEB": {"cidr": "10.1.100.0/24", "leaf": "LEAF-1", "vlan": 100, "svi": "10.1.100.1"},
    "DB":  {"cidr": "10.1.200.0/24", "leaf": "LEAF-1", "vlan": 200, "svi": "10.1.200.1"},
    "APP": {"cidr": "10.2.100.0/24", "leaf": "LEAF-2", "vlan": 100, "svi": "10.2.100.1"},
    "MGT": {"cidr": "10.2.50.0/24",  "leaf": "LEAF-2", "vlan": 300, "svi": "10.2.50.1"},
}

HOSTS: dict[str, dict] = {
    "Alpine-Linux-1": {"ip": "10.1.100.10", "zone": "WEB"},
    "Alpine-Linux-2": {"ip": "10.1.200.10", "zone": "DB"},
    "Alpine-Linux-3": {"ip": "10.2.100.10", "zone": "APP"},
    "Alpine-Linux-5": {"ip": "10.2.50.10",  "zone": "MGT"},
}

LEAFS: dict[str, dict] = {
    "LEAF-1": {"ssh_host": "192.168.122.20", "zones": ["WEB", "DB"]},
    "LEAF-2": {"ssh_host": "192.168.122.21", "zones": ["APP", "MGT"]},
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
