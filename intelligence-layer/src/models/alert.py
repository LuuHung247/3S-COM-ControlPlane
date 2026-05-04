from enum import IntEnum
from pydantic import BaseModel, Field


class AlertSeverity(IntEnum):
    P1_CRITICAL = 1
    P2_HIGH = 2
    P3_INFO = 3
    P4_AUDIT = 4


class SuricataAlert(BaseModel):
    timestamp: str = ""
    src_ip: str
    dest_ip: str = ""
    src_port: int = 0
    dest_port: int = 0
    proto: str = "tcp"
    alert: dict = Field(default_factory=dict)
    # Raw alert payload preserved for audit
    raw: dict = Field(default_factory=dict)

    @property
    def sid(self) -> int:
        return int(self.alert.get("signature_id", 0))

    @property
    def severity(self) -> int:
        return int(self.alert.get("severity", 4))

    @property
    def signature(self) -> str:
        return str(self.alert.get("signature", ""))

    @property
    def category(self) -> str:
        return str(self.alert.get("category", ""))

    @classmethod
    def from_raw(cls, data: dict) -> "SuricataAlert":
        return cls(
            timestamp=data.get("timestamp", ""),
            src_ip=data.get("src_ip", ""),
            dest_ip=data.get("dest_ip", ""),
            src_port=data.get("src_port", 0),
            dest_port=data.get("dest_port", 0),
            proto=data.get("proto", "tcp"),
            alert=data.get("alert", {}),
            raw=data,
        )
