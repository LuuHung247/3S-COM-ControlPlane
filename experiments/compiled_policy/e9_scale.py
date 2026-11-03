#!/usr/bin/env python3
"""E9: verifier scalability on synthetic knowledge bases.

A synthetic fabric has |Z| zones (one /24 each), a deny-by-default matrix with the
deployed allow density, and |S| catalogued signatures whose detection logic names one
source zone and a few destination zones. The program has the shape of the deployed ones:
protective rules first, then rules keyed on signature groups and verdicts (about 0.7 rules
per signature). Verification is timed on one core and with the domain split by signature
across p worker processes; peak resident memory is reported per process.

Usage: intelligence-layer/.venv/bin/python compiled_policy/e9_scale.py OUT.json
"""
import json
import random
import resource
import sys
import time
from multiprocessing import Pool
from pathlib import Path

IL = Path(__file__).resolve().parents[2] / "intelligence-layer"
sys.path.insert(0, str(IL))
from src.compiler import verifier as V  # noqa: E402
from src.compiler.dsl import Program  # noqa: E402
from src.compiler.kb import KBSnapshot, Signature  # noqa: E402
import ipaddress  # noqa: E402

ALLOW_DENSITY = 13 / 56          # deployed matrix: 13 allowed of 56 ordered pairs


def synth_kb(nz: int, ns: int, seed: int = 1) -> KBSnapshot:
    rnd = random.Random(seed)
    names = [f"Z{i:02d}" for i in range(nz)]
    zones = {n: {"name": n, "cidr": f"10.{100 + i // 200}.{i % 200}.0/24"} for i, n in enumerate(names)}
    matrix = {(a, b): ("ALLOW" if rnd.random() < ALLOW_DENSITY else "DENY")
              for a in names for b in names if a != b}
    sids = {}
    for j in range(ns):
        sid = 9100000 + j
        src = rnd.choice(names)
        dsts = rnd.sample([n for n in names if n != src], k=min(3, nz - 1))
        logic = f"TCP from {src} to [{', '.join(dsts)}]"
        sids[sid] = Signature(sid, 1 + j % 4, f"synthetic {sid}", logic, f"## SID {sid}\n{logic}")
    never_block = ["10.250.0.0/24"]
    kb = KBSnapshot(Path("synthetic"), {}, zones, matrix, sids, never_block, f"synth-{nz}-{ns}")
    kb._nets = [ipaddress.ip_network(c) for c in never_block]
    return kb


def synth_program(kb: KBSnapshot) -> Program:
    sids = sorted(kb.sids)
    rules = [
        {"id": "R0", "when": {"src_protected": True}, "then": {"action": "log_only"}},
        {"id": "R1", "when": {"src_zones": ["EXTERNAL"]}, "then": {"action": "log_only"}},
        {"id": "R2", "when": {"sid_known": False}, "then": {"action": "abstain"}},
        {"id": "R3", "when": {"severity_min": 3}, "then": {"action": "log_only"}},
    ]
    n_groups = max(1, int(0.7 * len(sids)) - 4)
    for g in range(n_groups):
        grp = sids[g::n_groups]
        verdict = ["DENY"] if g % 3 else ["ALLOW"]
        then = ({"action": "DROP", "scope": "flow", "ttl_seconds": 600, "confidence": 0.9}
                if verdict == ["DENY"] else {"action": "log_only"})
        rules.append({"id": f"G{g}", "when": {"sids": grp, "verdicts": verdict}, "then": then,
                      "rationale": "synthetic", "kb_refs": [f"SID {grp[0]}"]})
    rules.append({"id": "RD", "when": {"verdicts": ["DENY"]},
                  "then": {"action": "DROP", "scope": "flow", "ttl_seconds": 600, "confidence": 0.9},
                  "rationale": "deny-by-default", "kb_refs": ["policy-matrix"]})
    return Program.from_json({"rules": rules, "notes": "synthetic"}, kb.zone_names())


def _verify_part(args):
    nz, ns, part, parts = args
    kb = synth_kb(nz, ns)
    prog = synth_program(kb)
    keep = sorted(kb.sids)[part::parts]
    sub = KBSnapshot(kb.root, kb.texts, kb.zones, kb.matrix, {s: kb.sids[s] for s in keep},
                     kb.never_block, kb.digest)
    sub._nets = kb._nets
    t0 = time.perf_counter()
    n = viol = 0
    for f in V.domain(sub):                    # the unknown-signature value goes to part 0 only
        if f.sid == 0 and part != 0:
            continue
        n += 1
        viol += bool(V._check(sub, f, prog.evaluate(f)))
        V.realizable(sub, f)
    return n, viol, time.perf_counter() - t0, resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def deployed():
    """Wall time of the verifier on the deployed V0 program and ensemble (one core)."""
    import json as _j
    from src.compiler.dsl import Ensemble
    kb = KBSnapshot.load(IL / "knowledge_v2")
    art = Path(__file__).resolve().parents[1] / "results" / "compiled"
    single = Program.from_json(_j.load(open(art / "v2r_single.json"))["program"], kb.zone_names())
    ens = Ensemble([Program.from_json(x, kb.zone_names())
                    for x in _j.load(open(art / "v2r_ens5.json"))["ensemble"]])
    out = {}
    for name, prog in (("single", single), ("ensemble", ens)):
        t0 = time.perf_counter()
        rep = V.verify(kb, prog)
        out[name] = {"wall_s": round(time.perf_counter() - t0, 2), "ok": rep.ok, "points": rep.n_points}
    return out


def main(out):
    res = [{"deployed_v0": deployed()}]
    print(res[0], flush=True)
    for nz, ns, procs in ((8, 29, (1,)), (16, 60, (1, 8, 32)), (32, 120, (1, 8, 32)), (64, 250, (8, 32))):
        kb = synth_kb(nz, ns)
        size = (ns + 1) * 4 * (nz + 1) ** 2 * 2 * 7
        row = {"zones": nz, "signatures": ns, "domain": size, "rules": len(synth_program(kb).rules)}
        for p in procs:
            t0 = time.perf_counter()
            with Pool(p) as pool:
                parts = pool.map(_verify_part, [(nz, ns, i, p) for i in range(p)])
            wall = time.perf_counter() - t0
            assert sum(x[0] for x in parts) == size, (sum(x[0] for x in parts), size)
            row[f"wall_s_p{p}"] = round(wall, 1)
            row[f"peak_rss_mb_p{p}"] = round(max(x[3] for x in parts), 0)
            print(row, flush=True)
        res.append(row)
    Path(out).write_text(json.dumps(res, indent=1))


if __name__ == "__main__":
    main(sys.argv[1])
