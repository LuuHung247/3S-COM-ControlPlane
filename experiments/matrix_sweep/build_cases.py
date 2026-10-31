#!/usr/bin/env python3
"""Generate the full-matrix evaluation set mechanically.

The case list is a function of three artefacts that were authored before, and
independently of, this evaluation: the 8x8 policy matrix, the custom SID catalogue, and
the NEVER_BLOCK protected set. Every off-diagonal zone pair is covered, so the
evaluation space is defined by the architecture rather than chosen by the authors.

Ground truth per case:
  DENY pair, P1/P2 signature, source not protected   -> contain
  DENY pair, source protected (never-block)          -> do not contain (surface only)
  ALLOW pair, ALLOW-path override signature          -> contain (permitted-path abuse)
  ALLOW pair, informational/recon signature          -> do not contain (FP control)
  DENY pair with no covering signature               -> detection gap, no decision expected

Usage: intelligence-layer/.venv/bin/python matrix_sweep/build_cases.py [out.json]
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "intelligence-layer"))
from src.agent.safety.guardrails import is_protected_ip  # noqa: E402
from src.core import policy, sid_coverage, system_model  # noqa: E402
from src.core.policy import _ALLOW_PATH_ANOMALY_SIDS  # noqa: E402
from src.core.threat_playbook import SID_DETECTIONS  # noqa: E402

# Informational signatures used as the false-positive control on permitted paths.
RECON_SIDS = [9000040, 9000041, 9000042]


def zone_host(zone: str) -> str | None:
    for a in system_model.ASSETS.values():
        if a.zone == zone:
            return a.ip
    return None


def zone_port(zone: str, prefer: tuple[int, ...] = ()) -> int:
    ports = {s.port for a in system_model.ASSETS.values() if a.zone == zone for s in a.services}
    for p in prefer:
        if p in ports:
            return p
    return min(ports - {22}) if ports - {22} else 22


def _case(cid, src_z, dst_z, sid, verdict, expect, rationale, port=None):
    src, dst = zone_host(src_z), zone_host(dst_z)
    det = SID_DETECTIONS.get(sid)
    return {
        "case_id": cid, "src_zone": src_z, "dst_zone": dst_z,
        "src_ip": src, "dst_ip": dst,
        "dst_port": port if port is not None else zone_port(dst_z),
        "sid": sid, "severity": getattr(det, "severity_p_level", 2),
        "signature": getattr(det, "signature_msg", "") or "Suricata alert",
        "policy_verdict": verdict, "expected": expect, "rationale": rationale,
        "src_protected": bool(src and is_protected_ip(src)),
    }


def build() -> dict:
    cov = sid_coverage.coverage()
    cases, gaps = [], []
    for (src_z, dst_z), info in sorted(cov["pairs"].items()):
        verdict, sids = info["verdict"], info["sids"]
        src = zone_host(src_z)
        protected = bool(src and is_protected_ip(src))

        if verdict == "DENY":
            sid = sid_coverage.best_sid_for(src_z, dst_z)
            if sid is None:
                gaps.append({"pair": f"{src_z}->{dst_z}", "verdict": verdict,
                             "reason": "no custom signature covers this denied cell"})
                continue
            sev = getattr(SID_DETECTIONS[sid], "severity_p_level", 2)
            if protected:
                cases.append(_case(f"M-{src_z}-{dst_z}", src_z, dst_z, sid, verdict, "no_contain",
                                   "source is in the protected never-block set"))
            elif sev <= 2:
                cases.append(_case(f"M-{src_z}-{dst_z}", src_z, dst_z, sid, verdict, "contain",
                                   "denied cell, severe signature, source not protected"))
            else:
                cases.append(_case(f"M-{src_z}-{dst_z}", src_z, dst_z, sid, verdict, "no_contain",
                                   f"denied cell but signature is P{sev} (informational)"))
        else:
            # permitted path: content/behaviour abuse must be contained
            db = dst_z in ("DB-OLTP", "DB-ANALYTICS")
            abuse_sid = 9000072 if db else 9000050
            if abuse_sid in _ALLOW_PATH_ANOMALY_SIDS:
                cases.append(_case(f"A-{src_z}-{dst_z}", src_z, dst_z, abuse_sid, verdict,
                                   "no_contain" if protected else "contain",
                                   "source protected" if protected else
                                   "permitted path, content/behaviour abuse signature",
                                   port=5432 if db else None))
            # permitted path: informational signature is the false-positive control
            cases.append(_case(f"F-{src_z}-{dst_z}", src_z, dst_z, RECON_SIDS[0], verdict,
                               "no_contain", "permitted path, informational signature"))
    return {"generated_at": datetime.now(timezone.utc).isoformat(),
            "n_pairs": cov["n_pairs"], "n_deny": cov["n_deny"], "n_allow": cov["n_allow"],
            "detection_gaps": gaps, "cases": cases}


if __name__ == "__main__":
    data = build()
    c = data["cases"]
    print(f"pairs={data['n_pairs']} (DENY {data['n_deny']}, ALLOW {data['n_allow']})")
    print(f"cases={len(c)}  contain={sum(x['expected']=='contain' for x in c)}  "
          f"no_contain={sum(x['expected']=='no_contain' for x in c)}  "
          f"detection_gaps={len(data['detection_gaps'])}")
    for g in data["detection_gaps"]:
        print(f"  gap: {g['pair']} — {g['reason']}")
    if len(sys.argv) > 1:
        Path(sys.argv[1]).write_text(json.dumps(data, indent=2))
        print(f"saved {sys.argv[1]}")
