"""Flow event models for pure-log mode.

`SuricataFlowEvent` mirrors one `eve.json type:flow` record.
`AggregatedIPPair` is the per-window aggregation used by the agent reasoner,
following NetVigil Table 2 feature schema (NSDI'24).
"""
from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class SuricataFlowEvent(BaseModel):
    """One Suricata flow record (event_type=flow)."""
    timestamp: str = ""
    flow_id: int = 0
    in_iface: str = ""
    src_ip: str
    src_port: int = 0
    dest_ip: str = ""
    dest_port: int = 0
    proto: str = "tcp"
    app_proto: str = ""
    flow: dict = Field(default_factory=dict)      # pkts/bytes/state/age/reason/tx_cnt
    tcp: dict = Field(default_factory=dict)       # flags + state
    raw: dict = Field(default_factory=dict)

    @property
    def pkts_toserver(self) -> int:
        return int(self.flow.get("pkts_toserver", 0))

    @property
    def pkts_toclient(self) -> int:
        return int(self.flow.get("pkts_toclient", 0))

    @property
    def bytes_toserver(self) -> int:
        return int(self.flow.get("bytes_toserver", 0))

    @property
    def bytes_toclient(self) -> int:
        return int(self.flow.get("bytes_toclient", 0))

    @property
    def flow_state(self) -> str:
        return str(self.flow.get("state", "unknown"))

    @classmethod
    def from_raw(cls, data: dict) -> "SuricataFlowEvent":
        return cls(
            timestamp=data.get("timestamp", ""),
            flow_id=int(data.get("flow_id", 0)),
            in_iface=data.get("in_iface", ""),
            src_ip=data.get("src_ip", ""),
            src_port=int(data.get("src_port", 0)),
            dest_ip=data.get("dest_ip", ""),
            dest_port=int(data.get("dest_port", 0)),
            proto=data.get("proto", "tcp"),
            app_proto=data.get("app_proto", ""),
            flow=data.get("flow", {}),
            tcp=data.get("tcp", {}),
            raw=data,
        )


class AggregatedIPPair(BaseModel):
    """Per-window per-IP-pair aggregation. NetVigil Table 2 features."""
    src_ip: str
    dest_ip: str
    window_start: str
    window_end: str

    # Volume statistics (across flows in this pair)
    flow_count: int = 0
    tcp_flow_count: int = 0
    udp_flow_count: int = 0

    pkts_toserver_sum: int = 0
    pkts_toclient_sum: int = 0
    bytes_toserver_sum: int = 0
    bytes_toclient_sum: int = 0
    pkts_toserver_max: int = 0
    pkts_toclient_max: int = 0
    bytes_toserver_max: int = 0
    bytes_toclient_max: int = 0

    # Port-level (key signal for scan / lateral)
    unique_dst_ports: list[int] = Field(default_factory=list)
    unique_dst_port_count: int = 0
    unique_app_protos: list[str] = Field(default_factory=list)

    # Flow state distribution
    states_observed: list[str] = Field(default_factory=list)   # e.g. ["established", "new"]

    # Optional: src/dst zone if topology lookup succeeded
    src_zone: str = ""
    dest_zone: str = ""

    # Raw flow IDs included (for forensic trace)
    flow_ids: list[int] = Field(default_factory=list)
