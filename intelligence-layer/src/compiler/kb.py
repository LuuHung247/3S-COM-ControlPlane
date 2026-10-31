"""A snapshot of the architecture knowledge base, loaded from an arbitrary directory.

The runtime modules (topology, policy, invariants) bind the deployed knowledge base at
import time. The compiler instead takes the knowledge base as an input, so the same code
compiles the deployed fabric and any modified copy of it (new zones, new signatures),
and the compiled program records which snapshot it was built from.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ..agent.safety import guardrails

_YAML_BLOCK = re.compile(r"^```yaml\s*\n(.*?)^```\s*$", re.MULTILINE | re.DOTALL)
_SID_SECTION = re.compile(r"^## SID (\d+)\b.*?(?=^## SID |\Z)", re.MULTILINE | re.DOTALL)
_CIDR = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}")

# Files the compiler reads. Their bytes define the snapshot digest.
SOURCE_FILES = ("zones.md", "policy-matrix.md", "sids.md", "invariants.md", "assets.md",
                "severity-scoring.md", "baselines.md")
EXTERNAL = "EXTERNAL"


def _blocks(text: str) -> list:
    return [yaml.safe_load(m.group(1)) for m in _YAML_BLOCK.finditer(text)]


@dataclass
class Signature:
    sid: int
    severity: int
    msg: str
    logic: str
    section: str          # the full markdown section, prose included


@dataclass
class KBSnapshot:
    root: Path
    texts: dict[str, str]
    zones: dict[str, dict]
    matrix: dict[tuple[str, str], str]
    sids: dict[int, Signature]
    never_block: list[str]
    digest: str
    _nets: list = field(default_factory=list, repr=False)

    @classmethod
    def load(cls, root: str | Path) -> "KBSnapshot":
        root = Path(root)
        infra = root / "infra" if (root / "infra").is_dir() else root
        texts = {f: (infra / f).read_text(encoding="utf-8") for f in SOURCE_FILES}
        zones = {b["name"]: b for b in _blocks(texts["zones.md"]) if isinstance(b, dict) and "cidr" in b}
        matrix: dict[tuple[str, str], str] = {}
        for b in _blocks(texts["policy-matrix.md"]):
            if isinstance(b, dict) and "policy_matrix" in b:
                matrix = {(r["src_zone"], r["dst_zone"]): r["verdict"] for r in b["policy_matrix"]}
        sections = {int(m.group(1)): m.group(0).strip() for m in _SID_SECTION.finditer(texts["sids.md"])}
        sids = {}
        for b in _blocks(texts["sids.md"]):
            if isinstance(b, dict) and "sid" in b:
                sid = int(b["sid"])
                sids[sid] = Signature(sid, int(b.get("severity_p_level", 2)), b.get("signature_msg", ""),
                                      b.get("detection_logic", "") or "", sections.get(sid, ""))
        nb: list[str] = []
        for b in _blocks(texts["invariants.md"]):
            if isinstance(b, dict) and "never_block" in b:
                nb = [r["cidr"] for r in b["never_block"]]
        # The hard-coded floor in guardrails can only be extended by the knowledge base.
        never_block = list(dict.fromkeys(list(guardrails.NEVER_BLOCK) + nb))
        h = hashlib.sha256()
        for f in SOURCE_FILES:
            h.update(f.encode() + b"\0" + texts[f].encode())
        snap = cls(root, texts, zones, matrix, sids, never_block, h.hexdigest()[:16])
        snap._nets = [ipaddress.ip_network(c, strict=False) for c in never_block]
        return snap

    # ── lookups ────────────────────────────────────────────────────────────
    def zone_of(self, ip: str) -> str:
        try:
            addr = ipaddress.ip_address((ip or "").split("/")[0])
        except ValueError:
            return EXTERNAL
        for name, z in self.zones.items():
            if addr in ipaddress.ip_network(z["cidr"], strict=False):
                return name
        return EXTERNAL

    def verdict(self, src_zone: str, dst_zone: str) -> str:
        if EXTERNAL in (src_zone, dst_zone):
            return "EXTERNAL"
        if src_zone == dst_zone:
            return "INTRA"
        return self.matrix.get((src_zone, dst_zone), "DENY")

    def is_protected(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address((ip or "").split("/")[0])
        except ValueError:
            return False
        return any(addr in n for n in self._nets)

    def zone_fully_protected(self, zone: str) -> bool:
        """True when every host address of the zone is in the protected set."""
        net = ipaddress.ip_network(self.zones[zone]["cidr"], strict=False)
        return any(net.subnet_of(n) for n in self._nets if n.version == net.version)

    def zone_names(self) -> list[str]:
        return list(self.zones)

    # ── where each signature can fire, parsed from its detection logic ─────
    def _zones_in(self, text: str) -> set[str]:
        out = set()
        for c in _CIDR.findall(text):
            net = ipaddress.ip_network(c, strict=False)
            for name, z in self.zones.items():
                if ipaddress.ip_network(z["cidr"], strict=False).overlaps(net):
                    out.add(name)
        names = sorted(self.zones, key=len, reverse=True)
        for name in names:
            if re.search(rf"(?<![\w-]){re.escape(name)}(?![\w-])", text):
                out.add(name)
        if re.search(r"(?<![\w-])MON(?![\w-])", text) and "MONITORING" in self.zones:
            out.add("MONITORING")
        return out

    def sid_pairs(self, sid: int) -> set[tuple[str, str]] | None:
        """Ordered zone pairs the signature can fire on; None = not zone-scoped."""
        sig = self.sids.get(sid)
        m = re.search(r"\bfrom\b(.*?)\bto\b(.*)", sig.logic if sig else "", re.S)
        if not m:
            return None
        src_txt, dst_txt = m.group(1), m.group(2)
        all_z = set(self.zones)
        src = all_z - self._zones_in(src_txt) if "!" in src_txt else self._zones_in(src_txt)
        dst = all_z - self._zones_in(dst_txt) if "!" in dst_txt else self._zones_in(dst_txt)
        if "any zone" in dst_txt:
            dst = all_z
        if "external" in dst_txt.lower() or "!10." in dst_txt or "$EXTERNAL" in dst_txt:
            dst = dst | {EXTERNAL}
        if not src or not dst:
            return None
        return {(s, d) for s in src for d in dst if s != d}
