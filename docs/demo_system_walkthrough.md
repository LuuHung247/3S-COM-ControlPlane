# Demo Walkthrough — How the System Works

> A practical reference for the demo: every component, every data flow, where to
> point in code, and what each scenario actually does. Read top-to-bottom or jump
> to a section. Every claim is anchored to a file path.

---

## 0. Component map (one-screen)

```
                  ┌──────────────────────────────────────────────────┐
   DATA PLANE     │  SONiC Spine + 2 LEAFs (zones: WEB DB APP MGT)   │
                  │  ↑ tc-mirred copies all forwarded traffic to ⇣    │
                  │                                                  │
                  │   Suricata IDS  (on 10.10.6.238)                 │
                  │   /var/log/suricata/eve.json                     │
                  └──────────┬───────────────────────────────────────┘
                             │  tail eve.json
                             ▼
   ids-vm/ids-api.py    HTTP :8765      (host: 10.10.6.238)
   /alerts /flows /stream /health
                             │  SSE / GET
                             ▼
   ids-agent/main.go    HTTP :8766      (local, Go)
   /alerts /flows /rules (GET, POST)        ─────── proxies ──────┐
                             │                                     │
                             │ POST /alerts (synthetic)            │
                             ▼                                     │
   intelligence-layer   HTTP :8767       (FastAPI, Python)         │
   /alerts /admin/reset /events /health                            │
                             │                                     │
                             │ enforce() → POST /rules             │
                             ▼                                     │
   ids-agent /rules         (stamps source=agent server-side)      │
                             │                                     │
                             ▼                                     │
   Secure Framework     HTTP :9090       (10.10.6.238)             │
   /api/rules (CRUD)  + mTLS + RBAC + gNMI client pool             │
                             │                                     │
                             ▼ gNMI Set (YANG nos-iptables)        │
                  ┌──────────┴───────────────────────────────────┐ │
                  │  LEAF-1   LEAF-2  (SONiC, NETCONF/gNMI 6513) │◀┘
                  │  iptables FORWARD rules                       │
                  └───────────────────────────────────────────────┘

                                Next.js FE  :3000
                                /api/ids/* → ids-agent :8766
                                /api/intel/* → intel :8767
                                /api/ids/* (some) → IDS API :8765
```

---

## 1. Detection: Suricata → IDS API (the "monitor" feed the web shows)

Suricata is configured ([ids-vm/suricata-zt.yaml](../ids-vm/suricata-zt.yaml)) to write
EVE JSON to `/var/log/suricata/eve.json`. Each line is one event (`event_type` ∈
`alert | flow | http | dns | …`).

**`ids-vm/ids-api.py`** is a tiny Python HTTP server (port **8765**) that does
exactly two things: tail `eve.json` continuously into memory, and serve it.

- Tail loop ([ids-api.py:40-78](../ids-vm/ids-api.py)): handles file truncation /
  rotation (inotify-style by inode + size), parses each line, appends to two ring
  buffers (`_alerts`, `_flows`), and broadcasts new events to SSE subscribers.
- Endpoints ([ids-api.py:125-191](../ids-vm/ids-api.py)):
  - `GET /health` — liveness
  - `GET /alerts?last=N&since=ISO` — slice the alert buffer (used by the FE and
    the experiment harness)
  - `GET /alerts/clear` — set a server-side anchor timestamp (the harness calls
    this between runs)
  - `GET /flows?last=N&since=ISO` — same for `flow` events
  - `GET /stream` — Server-Sent Events: every newly-tailed alert/flow is pushed
    live

**So the answer to *"web đang lấy monitor từ Suricata qua nat đúng không?"*:** yes —
Suricata writes EVE on the IDS VM, `ids-api.py` tails it and exposes HTTP at
`10.10.6.238:8765`; the FE (or ids-agent) reads `/alerts`, `/flows`, and `/stream`
across the NAT.

---

## 2. The ids-agent bridge (local Go service, port 8766)

[ids-agent/main.go](../ids-agent/main.go) is a small Go service that does three
things:

1. **Proxies the IDS VM** (`/alerts`, `/flows`, `/health`) so the FE and the
   intelligence layer have a single local endpoint
   ([main.go:200-225](../ids-agent/main.go)).
2. **Bridges alerts as SSE** to subscribers (`/events`,
   [main.go:145](../ids-agent/main.go)) and tracks WS clients.
3. **Mediates rule pushes to the Secure Framework**:
   - `GET /rules` → proxies `SF /api/rules`, returning the live LEAF rule state
     ([main.go:240-250](../ids-agent/main.go)).
   - `POST /rules` → forces `source=agent` on the payload and forwards to
     `SF /api/rules` ([main.go:94-130, 227-238](../ids-agent/main.go)). This is the
     **provenance stamp**: SF will only accept agent-originated rules through this
     proxy (vs. operator-originated rules with `source=sdnc`).
   - `DELETE /rules/{id}` → removes an agent rule.

The harness, the agent's `IDSAgentProxyBackend`, and the FE all converge here.

---

## 3. Enforcement: ids-agent → Secure Framework → LEAFs

The **Secure Framework (SF)** lives at `10.10.6.238:9090`
([secure-framework/sam/role_api.py](../secure-framework/sam/role_api.py)). It:

- Holds an mTLS REST API and an in-process **gNMI client pool**
  (`secure-framework/gnmi/gnmiclient.py`).
- Enforces **RBAC**: each request authenticates via mTLS cert (the `OU` field maps
  to a role — `OU=auto` → `AGENT` may only `DROP`; `OU=sdnc` → operator role).
- On `GET /api/rules`: iterates every LEAF in the pool and does a gNMI
  `Get(path="/nos-iptables:acl/rule")` ([role_api.py:447-463](../secure-framework/sam/role_api.py));
  returns `{leaves: {leaf-1: {connected, rules: …}, leaf-2: …}}`.
- On `POST /api/rules`: validates the request (RBAC + schema), then does a gNMI
  `Set` against each LEAF's `nos-iptables` YANG container, installing an iptables
  `FORWARD` chain entry.

The LEAFs are SONiC switches running `nos-iptables` (Linux iptables in netns,
manipulated via gNMI). The actual datapath drop is a kernel iptables rule on the
LEAF's bridge interface.

So the path from "agent decides DROP" to "packet dropped at LEAF" is:

```
agent.process(alert)
  → IDSAgentProxyBackend.enforce(intent)          intelligence-layer/src/enforcement/ids_agent_proxy.py
  → POST http://ids-agent:8766/rules              (force source=agent)
  → POST http://sf:9090/api/rules                 (mTLS + RBAC)
  → gNMI Set nos-iptables:acl/rule → LEAF-1 / LEAF-2
  → kernel iptables FORWARD DROP applied
```

`GET /api/rules` walks the same path in reverse — that is how the FE and the harness
verify a rule is actually live on a LEAF, not just acknowledged.

---

## 4. The Intelligence Layer (the LLM agent, port 8767)

FastAPI app ([intelligence-layer/src/api/routes.py](../intelligence-layer/src/api/routes.py)).
Key endpoints:

- `POST /alerts` — inject a Suricata alert JSON for synchronous processing; returns
  a `DecisionResponse` (used by S14 and S15; also by the live SSE consumer when an
  alert flows in from the IDS API).
- `GET /events?kind=alert|flow|violation&limit=…` — server-side event store (Redis
  DB 1, 7-day retention) — what `fe/monitor` reads.
- `POST /admin/reset` — clears the in-memory rate limiter (used between eval runs).
- `GET /health`, `GET /events/stats`, `POST /admin/events/purge`, and a few KG /
  decision endpoints used by the FE.

The **decision pipeline** is in [intelligence-layer/src/agent/graph.py](../intelligence-layer/src/agent/graph.py)
(graph) and [nodes.py](../intelligence-layer/src/agent/nodes.py) (node bodies). One
alert in produces one decision through:

```
gate.should_process(alert)          # severity + dedup + whitelist + zone filter
  ↓
load_context        → topology + active rules + invariants for THIS alert
  ↓
classify_alert      → LLaMA 3.1-8B fast classifier: benign | suspicious | threat
  ↓ (if non-benign)
gather_context      → parallel: KG investigation (Neo4j), similar past incidents
                      (pgvector), reputation, host neighborhood, expected flows
  ↓
policy_decision     → GLM-4 ReAct (tool: query_kg); emits PolicyIntent
                      {action, src_ip, dst_ip, dst_port, ttl, confidence, …}
  ↓
validate_decision   → 9-layer safety: L1 schema, L3 topology, L4 immutable
                      allowlist, L4b off-target, L5 rate-limit, L6 severity,
                      L7 confidence; fail-closed → outcome ∈ {ENFORCED,
                      REJECTED, HELD, BENIGN, ERROR}
  ↓
PARALLEL FORK
  → enforce_path()        → ids_agent_proxy → SF → LEAF (only if action=DROP)
  → reasoning_trace()     → GLM-4 Stage-2 narrative for audit
  ↓
persist (Postgres decisions) + cache (Redis) + push SSE to FE + embed-on-write
```

The **safety architecture** referenced in the thesis (S14) is the combination of
[`safety/guardrails.py`](../intelligence-layer/src/agent/safety/guardrails.py) (the
NEVER_BLOCK allowlist) + `safety/validators.py` (L4b off-target + others) +
`pipeline/filters.py` (gate whitelist) + the prompt-hardening / input-sanitisation
in `agent/prompts.py`.

---

## 5. The Web FE (Next.js, port 3000)

Next.js app under [fe/src/app/](../fe/src/app). The FE never talks to backends
directly from the browser — it goes through its **own** API routes (Next.js route
handlers), which then call the actual services. This is convenient for CORS / auth.

Key pages and the endpoints they hit:

| FE page | FE route handler | Talks to |
|---|---|---|
| **Home** ([page.tsx:65-67](../fe/src/app/page.tsx)) | — direct fetch | `/api/ids/health`, `/api/ids/alerts?last=5`, `/api/ids/alerts` |
| **/monitor** (live monitor) ([monitor/page.tsx](../fe/src/app/monitor/page.tsx)) | `/api/intel/events?limit=600&kind=…`, `/api/ids/alerts?last=50`, `/api/ids/flows?last=100` | INTEL :8767 + ids-agent :8766 |
| **/kg** (knowledge graph viz) | `/api/intel/kg/json` | INTEL :8767 |
| **/decisions** | `/api/intel/decisions`, `/api/intel/decisions/[id]` | INTEL :8767 |
| Notification feed (always-on) | `/api/intel/decisions` | INTEL :8767 |

FE route handlers ([fe/src/app/api/](../fe/src/app/api/)) all read the backend URL
from env (`AGENT_URL=http://localhost:8766`, `INTEL_URL=http://localhost:8767`,
`IDS_API_URL=http://10.10.6.238:8765`). So the live demo can move services around
by changing one env file.

**The "monitor" page** reads from two sources in parallel:
1. `INTEL /events` — the event store (Redis DB 1, 7-day retention) that the agent
   feeds: alerts the agent received + flows it observed + violations it acted on.
2. `IDS API /alerts` and `/flows` (via the ids-agent proxy) — raw Suricata events
   in a 5-minute rolling buffer.

So when you watch /monitor during the demo, the events come **from Suricata via the
IDS VM via the ids-agent** for the raw feed, and **from the agent's Redis** for the
post-decision view (which alerts triggered which decisions).

---

## 6. How the scenario test scripts work

Each of the 13 functional scenarios is **two things**:

1. **A thin Python wrapper** in `experiments/scenarios/sNN_*.py` — sets the
   experiment name and preset, calls the harness. Example:
   `experiments/scenarios/s01_web_db_lateral.py` is 14 lines: it sets
   `EVAL_NAME="eval_web_db_lateral"` and runs `_apply_preset("web-db-lateral")`.

2. **A shell controller script on the MGT host** (Alpine VM at `10.10.6.238`,
   reachable through the GNS3 console at port **5016**), e.g.
   `/root/scenario/compromise-web.sh`. The script SSHes / `nc`s / `hping3`s from
   the appropriate workload to produce the attack traffic.

The harness ([experiments/harness/runner.py](../experiments/harness/runner.py)) does
the five-step loop for every scenario:

```
RESET     reset() at runner.py:398  ─ disarm prior attack, clear agent rules,
                                       reset rate limiter, flush Redis DB 0,
                                       set alert anchor
TRIGGER   run_scenario() at :481    ─ console_run("/root/scenario/<trigger>.sh")
                                       via telnet to MGT :5016
POLL      runner.py:502             ─ wait ≤120s for a decision matching scenario
VERIFY    rule_blocks_attacker()    ─ GET SF /api/rules, confirm a rule on the
                                       expected LEAF blocks the expected src
RESTORE   reset() again             ─ disarm + cleanup
```

The 13 scenarios + their MGT scripts (defined in
[runner.py:77-195](../experiments/harness/runner.py) `SCENARIO_PRESETS`):

| Wrapper | Preset key | MGT script | Attack |
|---|---|---|---|
| s01_web_db_lateral.py     | web-db-lateral  | compromise-web.sh         | WEB→DB:5432 direct |
| s02_web_app_burst.py      | web-app-burst   | compromise-web-burst.sh   | WEB→APP:8080 connection burst |
| s03_app_db_burst.py       | app-db-burst    | compromise-app-burst.sh   | APP→DB:5432 SYN burst |
| s04_app_db_sql.py         | app-db-sql      | compromise-app-sql.sh     | APP→DB destructive SQL pattern |
| s05_app_mgt_ssh.py        | app-mgt-ssh     | compromise-app-ssh.sh     | APP→MGT:22 cross-tier SSH |
| s06_vertical_scan.py      | yates-vscan     | compromise-yates-vscan.sh | port sweep on one host |
| s07_syn_flood.py          | yates-synflood  | compromise-yates-synflood.sh | single-source SYN flood |
| s08_distributed_syn_flood | yates-synddos   | compromise-yates-synddos.sh | multi-source SYN flood |
| s09_udp_flood.py          | yates-udpddos   | compromise-yates-udpddos.sh | high-rate UDP flood |
| s10_distributed_scan.py   | yates-distscan  | compromise-yates-distscan.sh | multi-host port probe |
| s11_multistage_propagation| yates-monkey    | compromise-yates-monkey.sh | worm-like scan + probe |
| s12_c2_beacon.py          | yates-c2        | compromise-yates-c2.sh    | low-and-slow C&C heartbeat |
| s13_unauth_db.py          | yates-unauthdb  | compromise-yates-unauthdb.sh | cross-zone DB access |

So during a live demo, when you run a scenario the chain is:

```
python3 scenarios/s01_web_db_lateral.py
  → runner: telnet MGT :5016, type "compromise-web.sh"
  → MGT runs the script: e.g. nc 10.1.200.10 5432 from WEB
  → packet hits LEAF-1, mirrored by tc to Suricata
  → Suricata fires SID 9000001, line appended to eve.json
  → ids-api.py tails it, broadcasts SSE + accepts GET /alerts
  → an upstream client (alert consumer) pushes the alert to INTEL /alerts
  → INTEL pipeline classifies → reasons → validates → enforces
  → ids_agent_proxy → SF /api/rules → gNMI Set → LEAF-1 iptables DROP
  → harness: GET SF /api/rules confirms the rule is on LEAF-1
  → PASS
```

### S14 and S15 are different — they bypass live traffic

`experiments/safety/s14_adversarial_safety.py` and
`experiments/generalization/s15_reasoning_ablation.py` do **not** trigger the MGT
console or generate real traffic. They craft synthetic Suricata alert JSON and POST
them directly to `INTEL /alerts`. This exercises the decision path
(gate → classify → gather → decide → validate → enforce) end-to-end without needing
the data-plane traffic — appropriate because S14 tests the safety architecture and
S15 tests reasoning, neither of which is a traffic-detection question. Enforced
rules are still real (live SF → LEAF) and are cleaned up after each run.

---

## 7. Quick demo checklist (what to point at)

1. **Show the topology / monitor.** Open the FE `/monitor`. The event stream is
   coming from `INTEL /events` (post-decision view) **and** `/api/ids/alerts` (raw
   Suricata via ids-api).
2. **Trigger a scenario.**
   `python3 experiments/scenarios/s01_web_db_lateral.py` — narrate the 5-step
   harness as it runs.
3. **In a second window, watch:**
   - `tail -f /var/log/suricata/eve.json` on the IDS VM, OR `curl :8765/stream`,
   - `curl :8767/events?kind=violation&limit=5` (the decision the agent took),
   - `curl :9090/api/rules` (the rule live on LEAFs).
4. **Run S14 to show safety.** A single command demonstrates the guardrails block
   adversarial inputs that would otherwise self-DoS a naive pipeline.
5. **Run S15 to show reasoning.** Shows the agent decides correctly on signatures
   absent from its table where a signature-keyed SOAR is structurally blind.
6. **Show the FE knowledge graph** at `/kg` — the on-demand `query_kg` data the
   agent uses for context.

---

## 8. Where to look in code (cheat sheet)

| You want to understand… | Open this |
|---|---|
| How Suricata alerts reach the system | `ids-vm/ids-api.py` |
| The Go bridge that proxies + stamps `source=agent` | `ids-agent/main.go` |
| The agent's HTTP surface | `intelligence-layer/src/api/routes.py` |
| The agent's decision pipeline | `intelligence-layer/src/agent/graph.py`, `agent/nodes.py` |
| Per-SID hint that's injected | `intelligence-layer/src/core/knowledge.py` + `agent/prompts.py` |
| Safety layers (allowlist, off-target) | `intelligence-layer/src/agent/safety/` |
| Gate filter chain | `intelligence-layer/src/pipeline/filters.py` |
| Push rule to LEAF | `intelligence-layer/src/enforcement/ids_agent_proxy.py` + `secure-framework/sam/role_api.py` |
| gNMI client | `secure-framework/gnmi/gnmiclient.py` |
| RBAC / mTLS role logic | `secure-framework/sam/role_policy.py`, `session_context.py` |
| Live experiment harness | `experiments/harness/runner.py` |
| Each scenario's preset | `experiments/harness/runner.py` `SCENARIO_PRESETS` dict |
| S14 / S15 drivers | `experiments/safety/s14_*.py`, `experiments/generalization/s15_*.py` |
| FE entry point | `fe/src/app/page.tsx`, `fe/src/app/monitor/page.tsx` |
| FE → backend route handlers | `fe/src/app/api/ids/*`, `fe/src/app/api/intel/*` |

---

## 9. Common demo questions you should be ready for

- **"Where does the alert come from?"** — Suricata writes EVE on the IDS VM,
  `ids-api.py` tails it; FE reads via `/api/ids/alerts`.
- **"How does the rule get on the LEAF?"** — agent → `ids-agent /rules` (stamps
  `source=agent`) → SF `/api/rules` (mTLS+RBAC) → gNMI Set against each LEAF's
  `nos-iptables:acl/rule`.
- **"How does the FE know the rule is on the LEAF?"** — `GET /api/ids/rules` →
  ids-agent proxies SF — SF queries every LEAF via gNMI and returns the
  consolidated view. So the FE shows the *actual* state of the data plane.
- **"What's the difference between source=sdnc and source=agent rules?"** — SDNC
  rules are baseline policy (deny-by-default + allow-paths) pushed by the
  controller; agent rules are dynamic, agent-decided DROPs with a TTL.
- **"Is the agent actually reasoning or just looking up the SID?"** — for known
  SIDs the prompt does carry a per-SID hint (severity, attack type, recommended
  action); S15 shows the agent still decides correctly when that hint is removed
  (unknown SID + generic message), so it is not a pure lookup. Honest framing in
  `docs/extended_evaluation_report.md`.
