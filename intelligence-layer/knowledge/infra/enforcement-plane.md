# Enforcement Plane Contract

Procedural knowledge for how the agent talks to Secure Framework. Endpoint contracts,
field naming, gotchas, failure modes, RBAC. Source of truth for *behaviour expectations*
of the SF REST API — not graph data, but knowledge agent must apply when constructing rules.

## Endpoints in scope

### `POST /api/rules`

Push a new rule. Synchronous — when 201 returns, rule is on iptables (or failure). Required body fields: rule_id (regex `[a-zA-Z0-9_\-]{1,64}`), action (must be DROP for AGENT role). Optional: src_ip/dst_ip (CIDR), protocol (default 'all'), src_port/dst_port (only for tcp/udp), priority (default 1000 — DANGEROUS, use 50), comment, ttl_seconds (stored but NOT enforced — agent must DELETE manually). Response 201 with `errors[]` indicates partial success on cross-leaf push — check errors even on success. POST same rule_id twice = REPLACE atomically (no 409). Server overrides: source forced to 'agent', comment auto-stamped if empty.

### `GET /api/rules`

List active rules from ALL LEAF nodes — live gNMI Get, no cache. Returns {leaves: {leaf-1: {connected, rules}, leaf-2: {...}}}. Field names are YANG-style (src-prefix, dst-prefix, rule-id with hyphens). Use to verify post-push state and detect partial application (rule on LEAF-1 but missing on LEAF-2).

### `GET /api/rules/{rule_id}`

Single rule status with per-LEAF presence. Returns 404 if rule not in any LEAF. Authoritative answer to 'is my rule actually active?'.

### `DELETE /api/rules/{rule_id}`

Revoke rule from all LEAFs. Idempotent — DELETE non-existent returns 200 with deleted_from=[]. Always safe to retry.

### `GET /health`

SF liveness probe. {status, service, mode}. Use before high-cost actions.

### `GET /pool`

SF→LEAF connection pool status. Check connections.admin=true for both leaves before cross-leaf rule push.

```yaml
endpoint_contracts:
- endpoint: POST /api/rules
  description: 'Push a new rule. Synchronous — when 201 returns, rule is on iptables (or failure). Required
    body fields: rule_id (regex `[a-zA-Z0-9_\-]{1,64}`), action (must be DROP for AGENT role). Optional:
    src_ip/dst_ip (CIDR), protocol (default ''all''), src_port/dst_port (only for tcp/udp), priority (default
    1000 — DANGEROUS, use 50), comment, ttl_seconds (stored but NOT enforced — agent must DELETE manually).
    Response 201 with `errors[]` indicates partial success on cross-leaf push — check errors even on success.
    POST same rule_id twice = REPLACE atomically (no 409). Server overrides: source forced to ''agent'',
    comment auto-stamped if empty.'
- endpoint: GET /api/rules
  description: 'List active rules from ALL LEAF nodes — live gNMI Get, no cache. Returns {leaves: {leaf-1:
    {connected, rules}, leaf-2: {...}}}. Field names are YANG-style (src-prefix, dst-prefix, rule-id with
    hyphens). Use to verify post-push state and detect partial application (rule on LEAF-1 but missing
    on LEAF-2).'
- endpoint: GET /api/rules/{rule_id}
  description: Single rule status with per-LEAF presence. Returns 404 if rule not in any LEAF. Authoritative
    answer to 'is my rule actually active?'.
- endpoint: DELETE /api/rules/{rule_id}
  description: Revoke rule from all LEAFs. Idempotent — DELETE non-existent returns 200 with deleted_from=[].
    Always safe to retry.
- endpoint: GET /health
  description: SF liveness probe. {status, service, mode}. Use before high-cost actions.
- endpoint: GET /pool
  description: SF→LEAF connection pool status. Check connections.admin=true for both leaves before cross-leaf
    rule push.
```

## Field name mapping

Field names drift across REST request body, YANG/gNMI notification, and ConfigDB key.
Most-confused fields are flagged ⚠️.

```yaml
field_name_mapping:
- rest_request: rule_id or rule-id
  yang_gnmi: rule-id
  configdb: key
- rest_request: action
  yang_gnmi: action
  configdb: action
- rest_request: src_ip or src-ip
  yang_gnmi: src-ip
  configdb: src-prefix ⚠️
- rest_request: dst_ip or dst-ip
  yang_gnmi: dst-ip
  configdb: dst-prefix ⚠️
- rest_request: protocol
  yang_gnmi: protocol
  configdb: protocol
- rest_request: src_port
  yang_gnmi: src-port
  configdb: src-port
- rest_request: dst_port
  yang_gnmi: dst-port
  configdb: dst-port
- rest_request: priority
  yang_gnmi: priority
  configdb: priority
- rest_request: source
  yang_gnmi: source
  configdb: source
- rest_request: ttl_seconds
  yang_gnmi: ttl-seconds
  configdb: ttl-seconds
```

## Critical gotchas

- PRIORITY GOTCHA: priority >= 1000 (default) causes `iptables -A FORWARD` (append) — rule lands AFTER `nos:zt-default-drop` and is silently ineffective. Agent block rules MUST use priority=50 (or any value <100, which translates to `iptables -I FORWARD 1`).
- TTL NOT ENFORCED: ttl_seconds is stored but no background expiration runs. Agent maintains its own {rule_id → expire_at} map and calls DELETE when expired. Idempotent DELETE — safe to retry.
- AGENT ROLE = DROP ONLY: SF outbound cert has OU=auto. Bridge enforces AGENT role: action MUST be DROP, source forced to 'agent'. Agent gửi action=ACCEPT → HTTP 400 'AGENT role may only push DROP rules' from adapter.
- FIELD NAME DRIFT: POST request accepts both src_ip and src-ip. GET response uses YANG-style src-prefix in ConfigDB and src-ip in gNMI notification. Parse code MUST handle both forms.
- PARTIAL FAILURE ON CROSS-LEAF: HTTP 201 with errors[] non-empty means rule applied to subset of LEAFs (e.g., LEAF-1 ok, LEAF-2 timeout). Defense-in-depth broken. Default policy: rollback DELETE and retry once both leaves connected.
- SOURCE SEMANTICS WIN: source field is server-overwritten to 'agent' in current cert configuration (OU=auto). What client sends in body is irrelevant — provenance is decided by SF outbound cert.

```yaml
critical_gotchas:
- 'PRIORITY GOTCHA: priority >= 1000 (default) causes `iptables -A FORWARD` (append) — rule lands AFTER
  `nos:zt-default-drop` and is silently ineffective. Agent block rules MUST use priority=50 (or any value
  <100, which translates to `iptables -I FORWARD 1`).'
- 'TTL NOT ENFORCED: ttl_seconds is stored but no background expiration runs. Agent maintains its own
  {rule_id → expire_at} map and calls DELETE when expired. Idempotent DELETE — safe to retry.'
- 'AGENT ROLE = DROP ONLY: SF outbound cert has OU=auto. Bridge enforces AGENT role: action MUST be DROP,
  source forced to ''agent''. Agent gửi action=ACCEPT → HTTP 400 ''AGENT role may only push DROP rules''
  from adapter.'
- 'FIELD NAME DRIFT: POST request accepts both src_ip and src-ip. GET response uses YANG-style src-prefix
  in ConfigDB and src-ip in gNMI notification. Parse code MUST handle both forms.'
- 'PARTIAL FAILURE ON CROSS-LEAF: HTTP 201 with errors[] non-empty means rule applied to subset of LEAFs
  (e.g., LEAF-1 ok, LEAF-2 timeout). Defense-in-depth broken. Default policy: rollback DELETE and retry
  once both leaves connected.'
- 'SOURCE SEMANTICS WIN: source field is server-overwritten to ''agent'' in current cert configuration
  (OU=auto). What client sends in body is irrelevant — provenance is decided by SF outbound cert.'
```

## Failure modes

### `gnmi-timeout-all-leaves`

- **Trigger**: Both LEAF mgmt unreachable
- **REST status**: 500
- **Body signature**: {success:false, error:'<host>: deadline exceeded'}
- **State after**: No rule applied anywhere
- **Agent action**: Retry with exponential backoff (60s, 300s). After 3 retries, escalate. NEVER SSH to LEAF.

### `gnmi-timeout-partial`

- **Trigger**: One LEAF mgmt unreachable during cross-leaf push
- **REST status**: 201 (partial success)
- **Body signature**: {success:true, pushed_to:['ip1'], errors:['ip2: ...']}
- **State after**: Rule applied on one LEAF only — defense-in-depth gap
- **Agent action**: Default: rollback via DELETE then retry when both leaves up. Alternative: accept partial if source-leaf rule already blocks the threat.

### `bridge-validator-reject`

- **Trigger**: Schema invalid, AGENT push non-DROP, source mismatch
- **REST status**: 400
- **Body signature**: {success:false, error:'<validator message>'}
- **State after**: Atomic — no rule applied
- **Agent action**: DETERMINISTIC reject. Do NOT retry. Fix the rule construction or escalate.

### `agent-role-non-drop`

- **Trigger**: Agent submitted action=ACCEPT or RETURN
- **REST status**: 400
- **Body signature**: {success:false, error:'AGENT role may only push DROP rules'}
- **State after**: No rule applied
- **Agent action**: Code bug — agent should never construct non-DROP. Escalate as defect.

### `duplicate-rule-id`

- **Trigger**: POST same rule_id twice
- **REST status**: 201
- **Body signature**: {success:true} — REPLACE semantics, not 409
- **State after**: Old rule replaced atomically with new field values
- **Agent action**: No action needed — REPLACE is intentional. Use deterministic rule_id (sha256 of flow tuple) to dedupe.

### `sf-unreachable`

- **Trigger**: SF process down, network partition between agent and SF
- **REST status**: ConnectionError (no HTTP response)
- **Body signature**: N/A
- **State after**: UNKNOWN — agent cannot determine if rule is active
- **Agent action**: ESCALATE IMMEDIATELY. Agent has NO fallback path — single source of truth invariant.

```yaml
failure_modes:
- name: gnmi-timeout-all-leaves
  trigger: Both LEAF mgmt unreachable
  rest_status: '500'
  body_signature: '{success:false, error:''<host>: deadline exceeded''}'
  state: No rule applied anywhere
  agent_action: Retry with exponential backoff (60s, 300s). After 3 retries, escalate. NEVER SSH to LEAF.
- name: gnmi-timeout-partial
  trigger: One LEAF mgmt unreachable during cross-leaf push
  rest_status: 201 (partial success)
  body_signature: '{success:true, pushed_to:[''ip1''], errors:[''ip2: ...'']}'
  state: Rule applied on one LEAF only — defense-in-depth gap
  agent_action: 'Default: rollback via DELETE then retry when both leaves up. Alternative: accept partial
    if source-leaf rule already blocks the threat.'
- name: bridge-validator-reject
  trigger: Schema invalid, AGENT push non-DROP, source mismatch
  rest_status: '400'
  body_signature: '{success:false, error:''<validator message>''}'
  state: Atomic — no rule applied
  agent_action: DETERMINISTIC reject. Do NOT retry. Fix the rule construction or escalate.
- name: agent-role-non-drop
  trigger: Agent submitted action=ACCEPT or RETURN
  rest_status: '400'
  body_signature: '{success:false, error:''AGENT role may only push DROP rules''}'
  state: No rule applied
  agent_action: Code bug — agent should never construct non-DROP. Escalate as defect.
- name: duplicate-rule-id
  trigger: POST same rule_id twice
  rest_status: '201'
  body_signature: '{success:true} — REPLACE semantics, not 409'
  state: Old rule replaced atomically with new field values
  agent_action: No action needed — REPLACE is intentional. Use deterministic rule_id (sha256 of flow tuple)
    to dedupe.
- name: sf-unreachable
  trigger: SF process down, network partition between agent and SF
  rest_status: ConnectionError (no HTTP response)
  body_signature: N/A
  state: UNKNOWN — agent cannot determine if rule is active
  agent_action: ESCALATE IMMEDIATELY. Agent has NO fallback path — single source of truth invariant.
```

## RBAC contract

Agent operates under cert OU=auto, role AGENT. AGENT can ONLY push DROP rules.
For ACCEPT rules (e.g., to whitelist legitimate flow), agent MUST escalate to operator
with OU=sdnc (role ADMIN). Agent cannot do this autonomously.

Defense-in-depth on enforcement plane:
1. SF adapter rejects non-DROP from AGENT role (HTTP 400)
2. nos-acl-bridge validators on each LEAF re-verify role+source
3. Both must pass — no single bypass.

```yaml
rbac_contract: 'Agent operates under cert OU=auto, role AGENT. AGENT can ONLY push DROP rules.

  For ACCEPT rules (e.g., to whitelist legitimate flow), agent MUST escalate to operator

  with OU=sdnc (role ADMIN). Agent cannot do this autonomously.


  Defense-in-depth on enforcement plane:

  1. SF adapter rejects non-DROP from AGENT role (HTTP 400)

  2. nos-acl-bridge validators on each LEAF re-verify role+source

  3. Both must pass — no single bypass.'
```
