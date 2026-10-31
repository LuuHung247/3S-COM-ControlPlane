#!/usr/bin/env python3
"""Build modified copies of the knowledge base for the drift experiment (E2).

Each variant is a realistic change an operations team makes between two compilations:
  v1_new_sigs   six new custom signatures (two detect abuse inside permitted connections,
                four are controls: policy violation, operational burst, audit, informational)
  v2_new_zone   a ninth zone (PAYMENTS, crown-jewel) with its matrix rows, gateway and
                two zone-pair signatures
  v3_retune     three documented responses changed in prose only (structured fields unchanged)
  v4_all        all of the above
The decisions each change implies are written into the prose exactly as the existing
catalogue states them (the **Response** field), so ground truth stays mechanical.

Usage: python3 compiled_policy/make_variants.py   (writes compiled_policy/kb_variants/)
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parents[1] / "intelligence-layer" / "knowledge_v2" / "infra"
OUT = HERE / "kb_variants"


def sid_entry(sid, sev, title, mitre, response, fp, trigger, logic, desc):
    return f"""
## SID {sid} — {title}

**Severity P{sev}**  ·  **MITRE**: {mitre}  ·  **Response**: {response}  ·  **FP likelihood**: {fp}

Detection trigger: {trigger}

```yaml
sid: {sid}
severity_p_level: {sev}
signature_msg: {title}
production_description: {desc}
mitre_tactic: {mitre.split(' / ')[0]}
mitre_technique: {mitre.split(' / ')[-1]}
detection_logic: {logic}
```
"""


NEW_SIGS = [
    sid_entry(9000073, 1, "PostgreSQL COPY TO PROGRAM in DB stream",
              "TA0002 Execution / T1059 Command and Scripting Interpreter",
              "DROP src_ip + escalate to SOC", "very low",
              "COPY ... TO PROGRAM executes an OS command on the database server. No application "
              "in this fabric uses it; on any DB connection, including the permitted APP-CORE and "
              "WORKER paths, it means the client is running commands on the database host.",
              'TCP to [10.1.200.0/24,10.3.200.0/24] [5432] pcre:"/COPY\\s+.+\\s+TO\\s+PROGRAM/i"',
              "Server-side command execution through the SQL channel."),
    sid_entry(9000074, 2, "Unbounded SELECT burst from a single client",
              "TA0010 Exfiltration / T1213 Data from Information Repositories",
              "DROP src_ip", "low",
              "More than 50 unbounded SELECT * statements per minute from one client. Application "
              "queries are paginated; this shape is bulk extraction over a permitted DB grant.",
              'TCP to [10.1.200.0/24,10.3.200.0/24] [5432,3306] pcre:"/SELECT\\s+\\*\\s+FROM\\s+\\w+\\s*;/i" threshold:50/60s,by_src',
              "Bulk extraction through a legitimate database grant."),
    sid_entry(9000075, 2, "Directory authentication burst",
              "TA0006 Credential Access / T1110 Brute Force",
              "log_only + escalate — usually batch jobs re-authenticating after a rotation", "high",
              "More than 100 Kerberos/LDAP requests per minute from one source. Nightly batch jobs "
              "and secret rotation produce the same shape; a human decides.",
              "TCP to $HOME_NET [88,389,636] threshold:100/60s,by_src",
              "Authentication burst; ambiguous between brute force and batch re-authentication."),
    sid_entry(9000076, 3, "Internal TLS certificate expired",
              "N/A / N/A", "log_only", "n/a",
              "TLS handshake presenting an expired certificate between internal services. Hygiene finding.",
              "TLS from $HOME_NET to $HOME_NET tls.cert_expired",
              "Certificate hygiene."),
    sid_entry(9000077, 1, "SSH from WORKER to APP-CORE - lateral movement",
              "TA0008 Lateral Movement / T1021 Remote Services", "DROP src_ip", "very low",
              "WORKER may only reach DB-OLTP. An SSH attempt toward APP-CORE is a policy violation "
              "and a lateral-movement step.",
              "TCP SYN from 10.4.100.0/24 to 10.2.100.0/24 dst_port 22",
              "Worker tier attempting interactive access to the business-logic tier."),
    sid_entry(9000078, 2, "Message-queue consumer offset reset storm",
              "N/A / N/A", "log_only — operational fault, not an attack", "high",
              "More than 200 consumer-group offset resets per minute against the WORKER queue. "
              "Caused by crash-looping consumers.",
              "TCP to [10.4.100.0/24] [9092] threshold:200/60s,by_src",
              "Operational fault signal on the job queue."),
]

ZONE_PAYMENTS = """
## PAYMENTS — Card-payment tokenisation and settlement service (PCI-DSS scope)

CIDR `10.5.100.0/24` on `LEAF-5` (VLAN 100, SVI 10.5.100.1). Trust level: **crown-jewel**, criticality: **critical**.

```yaml
name: PAYMENTS
cidr: 10.5.100.0/24
leaf: LEAF-5
vlan: 100
svi_gateway: 10.5.100.1
purpose: Card-payment tokenisation and settlement (PCI-DSS scope). Called only by APP-CORE; writes settlement records to DB-OLTP.
trust_level: crown-jewel
criticality: critical
```
"""

ASSET_PAYMENTS = """
## pay-01 (10.5.100.10)

**Zone**: PAYMENTS  ·  **Tier**: payment tier  ·  **Criticality**: critical  ·  **Data**: restricted  ·  **Owner**: payments

**Role**: Card tokenisation and settlement API

**If compromised**:

> Cardholder data exposure and fraudulent settlement. Any connection into PAYMENTS from a zone other than APP-CORE, MGT or MONITORING is a violation.

**If blocked**:

> Checkout fails for every customer; settlement backlog accumulates. Highest-cost block target after DB-OLTP.

```yaml
ip: 10.5.100.10
hostname: pay-01
zone: PAYMENTS
tier: payment tier
role: Card tokenisation and settlement API
criticality: critical
data_classification: restricted
secondary_host_ip: 10.5.100.11
services:
- port: 8443
  proto: tcp
  name: payments-api
  facing: internal
  purpose: Tokenisation and settlement API for APP-CORE
expected_inbound_sources:
- APP-CORE
- MGT
- MONITORING
```
"""

PAYMENTS_SIGS = [
    sid_entry(9000014, 1, "Unauthorised zone to PAYMENTS",
              "TA0008 Lateral Movement / T1021 Remote Services", "DROP src_ip", "very low",
              "Only APP-CORE (and MGT/MONITORING) may reach PAYMENTS. Any other zone initiating "
              "toward it is a hard violation against PCI scope.",
              "TCP SYN from [10.1.100.0/24,10.3.100.0/24,10.4.100.0/24,10.1.200.0/24,10.3.200.0/24] to 10.5.100.0/24",
              "Unauthorised access into the payment tier."),
    sid_entry(9000015, 1, "PAYMENTS initiating outside its settlement path",
              "TA0010 Exfiltration / T1048 Exfiltration Over Alternative Protocol", "DROP src_ip", "very low",
              "PAYMENTS may only write to DB-OLTP. Any other outbound connection suggests card data "
              "leaving the tier.",
              "TCP SYN from 10.5.100.0/24 to [10.1.100.0/24,10.3.100.0/24,10.2.100.0/24,10.4.100.0/24,10.3.200.0/24,10.2.50.0/24,10.4.200.0/24]",
              "Payment tier initiating outside settlement."),
]

MATRIX_PAYMENTS = """- src_zone: APP-CORE
  dst_zone: PAYMENTS
  verdict: ALLOW
- src_zone: PAYMENTS
  dst_zone: DB-OLTP
  verdict: ALLOW
- src_zone: MONITORING
  dst_zone: PAYMENTS
  verdict: ALLOW
- src_zone: MGT
  dst_zone: PAYMENTS
  verdict: ALLOW
"""

RETUNE = [   # (sid, old response, new response) — prose only
    (9000060, "DROP src_ip after correlate",
     "DROP src_ip — beacon destinations are now confirmed by threat intelligence, no correlation needed"),
    (9000052, "log_only + escalate",
     "DROP src_ip — upstream scrubbing was decommissioned; the agent now contains UDP floods"),
    (9000050, "DROP src_ip",
     "log_only — SYN floods are absorbed by the new upstream SYN proxy; blocking the source cuts legitimate retries"),
]


def _set_response(text: str, sid: int, old: str, new: str) -> str:
    pat = re.compile(rf"(## SID {sid} —.*?\*\*Response\*\*: ){re.escape(old)}(\s+·)", re.S)
    out, n = pat.subn(lambda m: m.group(1) + new + m.group(2), text, count=1)
    assert n == 1, f"response of {sid} not found"
    return out


def apply(dst: Path, sigs=False, zone=False, retune=False) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    (dst / "infra").mkdir(parents=True)
    for f in SRC.iterdir():
        shutil.copy(f, dst / "infra" / f.name)
    p = lambda name: dst / "infra" / name  # noqa: E731
    if sigs:
        p("sids.md").write_text(p("sids.md").read_text() + "".join(NEW_SIGS))
    if zone:
        p("zones.md").write_text(p("zones.md").read_text() + ZONE_PAYMENTS)
        p("assets.md").write_text(p("assets.md").read_text() + ASSET_PAYMENTS)
        p("sids.md").write_text(p("sids.md").read_text() + "".join(PAYMENTS_SIGS))
        pm = p("policy-matrix.md").read_text()
        anchor = "- src_zone: MGT\n  dst_zone: MONITORING\n  verdict: ALLOW\n"
        assert anchor in pm
        p("policy-matrix.md").write_text(pm.replace(anchor, anchor + MATRIX_PAYMENTS, 1))
        inv = p("invariants.md").read_text()
        anchor = "- cidr: 192.168.122.205/32\n"
        assert anchor in inv
        p("invariants.md").write_text(inv.replace(
            anchor, "- cidr: 10.5.100.1/32\n  rationale: PAYMENTS zone SVI gateway — blocking takes checkout offline\n"
            + anchor, 1))
    if retune:
        t = p("sids.md").read_text()
        for sid, old, new in RETUNE:
            t = _set_response(t, sid, old, new)
        p("sids.md").write_text(t)


if __name__ == "__main__":
    for name, kw in (("v1_new_sigs", dict(sigs=True)), ("v2_new_zone", dict(zone=True)),
                     ("v3_retune", dict(retune=True)),
                     ("v4_all", dict(sigs=True, zone=True, retune=True))):
        apply(OUT / name, **kw)
        print("wrote", OUT / name)
