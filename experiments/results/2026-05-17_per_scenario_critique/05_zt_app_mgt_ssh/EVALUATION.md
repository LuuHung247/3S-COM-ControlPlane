# Scenario 05 — ZT APP→MGT/WEB Cross-tier SSH

## Scenario context

| Field | Value |
|---|---|
| Wrapper | `scenarios/zt_06_app_mgt_ssh.py` |
| Trigger | `compromise-app-ssh.sh` → APP touch `/tmp/compromised-ssh` |
| Attack pattern | APP fires `nc 10.1.200.10:22` (DB) + `nc 10.1.100.10:22` (WEB) |
| Preset expected SID | 9000005 (APP→MGT:22) |
| **Actual SID fired** | 9000003 (APP→WEB:22) — eval expected wrong dst |
| ZT context | Cross-tier SSH always anomalous — chỉ MGT bastion mới được SSH workloads |

## Eval result

| Metric | Value |
|---|---|
| Outcome | **PASS** ✅ enforced (lenient src match worked) |
| Actual SID fired | 9000003 (APP→WEB:22 lateral) |
| Confidence | 0.92 |
| Action | DROP enforced, TTL 1800s |
| MITRE | TA0008 Lateral Movement / T1021.004 Remote Services: SSH |

**Note**: Preset expected dst=10.2.50.10 (MGT) nhưng `attacker-app.sh` fires APP→DB:22 + APP→WEB:22, không phải APP→MGT:22. → Eval lenient match (src=APP) accept SID 9000003 → PASS.

## 🧠 Agent reasoning (SID 9000003)

### Hypotheses (2)
- **Lateral Movement (p=0.92)** — "Adversary on app-01 pivoting to web-01 via SSH. Port 22 traffic from APP zone to WEB zone violates 'MGT-only' SSH policy. **Counter: None; baseline explicitly forbids workload-to-workload SSH.**"
- **Operational Error (p=0.08)** — DevOps engineer bypassing bastion. Counter: ZT mandates MGT bastion; no prior history.

### Reasoning chain (6 steps)
1. Observed: APP (10.2.100.10) → WEB (10.1.100.10):22 (SSH)
2. **Baseline check**: "System model explicitly states 'Workload-to-workload SSH (WEB/APP/DB → port 22) — only MGT may SSH into workloads' is anomalous"
3. Threat pattern match: `cross_tier_admin_port` → MITRE T1021.004
4. **Severity scoring quantitative**: dst_port_in_admin_set (+3) + cross_zone_policy_violation (+4) = **7 points → P2 (High)**
5. Hard overrides verified: src ≠ MGT, dst not in NEVER_BLOCK, conf 0.92 > 0.85 threshold
6. Targeted block (src+dst+port) preserve APP→DB OLTP traffic

### Alternative actions
- IF alert repeats after TTL → escalate full-source block (persistent lateral = compromise)
- IF APP→DB OLTP outage detected → revoke (could be false positive impacting critical path)

### Follow-ups
- Monitor APP→MGT connections (credential abuse indicator)
- Monitor WEB→DB direct (bypass of application logic)
- Correlate với SID 9000035 (SSH workload tiers) for kill-chain progression

---

## 📊 Evaluation

### ✅ Đặc biệt tốt

1. **System model citation chính xác (step 2)**
   - "only MGT may SSH into workloads" — đúng theo KG zones.md
   - Không phải hallucinate, cite explicit baseline rule

2. **Severity scoring transparent (step 4)**
   - **"dst_port_in_admin_set (+3) + cross_zone_policy_violation (+4) = 7 points → P2"**
   - Quantitative breakdown của decision, không opaque
   - Reproducible per severity-scoring.md rubric

3. **MITRE T1021.004 specific**
   - Không chỉ T1021 generic, mà T1021.**004** = "Remote Services: SSH"
   - Agent fine-grained MITRE awareness

4. **Counter-hypothesis logic mạnh**
   - "DevOps bypass bastion" hypothesis — realistic operational concern
   - Counter chính xác: "ZT mandates MGT bastion + no prior history"
   - Loại bỏ FP đúng

5. **Cross-correlation follow-ups**
   - Monitor APP→MGT (credential reuse indicator)
   - Correlate SID 9000035 (workload SSH chain)
   - **Threat hunting mindset** — anticipate next stage

### ⚠️ Điểm note

1. **Hypothesis probabilities mismatch**
   - Description says "p=0.92" và "p=0.08" 
   - Nhưng JSON `probability` field cho cả 2 đều 0.5
   - Có bug nhỏ trong agent format output (mismatch description text vs probability field). Decision vẫn enforce đúng nhờ confidence 0.92.

2. **Preset mismatch** (eval-level, not agent)
   - Preset expected APP→MGT:22 nhưng attacker-app.sh fires APP→DB:22 + APP→WEB:22
   - **Đây là bug spec**, không phải agent. Nên fix preset (đổi target_dst_ip=10.1.100.10) hoặc thêm APP→MGT vào attacker script.

### 🎯 Architectural validity

```
Per ZT theory:
  Workload-to-workload SSH = always anomalous
  Only MGT bastion → workloads = allowed
  
Per agent's reasoning:
  Step 2: explicit reference "MGT-only SSH policy"
  Step 4: severity score +3 admin port + +4 cross-zone = 7pts P2
  Step 6: targeted block preserve APP→DB OLTP path
  
→ Architecture correctly understood. Quantitative severity scoring trans-
  parent + reproducible.
```

### 📐 So sánh business semantic

| Expectation | Agent response | Match? |
|---|---|---|
| Detect cross-tier SSH (lateral) | ✓ SID 9000003 → DROP | ✓ |
| Identify "MGT-only SSH" baseline | ✓ Cite explicit rule | ✓ |
| Quantitative severity (7 pts = P2) | ✓ Breakdown shown | ✓ |
| MITRE specific (T1021.004) | ✓ Subtechnique cited | ✓ |
| Anticipate credential reuse | ✓ Follow-up monitor APP→MGT | ✓ |
| Preserve critical OLTP path | ✓ Targeted block, không full-source | ✓ |

**→ Architecturally correct, business-aware. Severity scoring transparent là điểm mạnh.**

## Verdict

**Agent behavior CORRECT** với reasoning rich. 

**Cần action**: fix preset `app-mgt-ssh` để target_dst_ip = 10.1.100.10 (WEB) hoặc 10.1.200.10 (DB), không phải 10.2.50.10 (MGT) — vì attacker-app.sh không fire SSH tới MGT. **Bug spec, không phải bug agent**.

Highlight cho luận văn: **severity scoring transparency** (step 4) — reviewer dễ verify "agent quyết định DROP vì 7 điểm severity match P2 threshold". Đây là loại "explainability" rất quan trọng cho audit + compliance.
