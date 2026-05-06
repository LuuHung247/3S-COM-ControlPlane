"use client";

import { useCallback, useEffect, useState } from "react";

interface Rule {
  "rule-id": string;
  action: "DROP" | "ACCEPT" | "RETURN";
  "src-ip"?: string;
  "src-prefix"?: string;
  "dst-ip"?: string;
  "dst-prefix"?: string;
  protocol?: string;
  "src-port"?: string | number;
  "dst-port"?: string | number;
  priority?: number | string;
  source?: string;
  comment?: string;
  "ttl-seconds"?: number | string;
}

interface LeafData {
  connected: boolean;
  rules?: unknown;
  error?: string;
}

interface AgentDecision {
  id: string;
  timestamp: string;
  alert_sid: number;
  attacker_ip: string;
  decision: "enforced" | "dry_run";
  dry_run: boolean;
  action: string | null;
  block_src: string | null;
  block_dst: string | null;
  confidence: number | null;
  latency_ms: number;
}

interface DecisionDetail {
  id: string;
  alert_sid: number;
  alert_src_ip: string;
  outcome: string;
  action: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  confidence: number | null;
  rule_id: string | null;
  ttl_seconds: number | null;
  latency_ms: number;
  trace_id: string | null;
  primary_hypothesis: string | null;
  hypotheses: Array<{ name?: string; description?: string; probability?: number }>;
  reasoning: string[];
  alternative_actions: Array<{ trigger_condition?: string; action?: string; rationale?: string } | string>;
  rollback_plan: { trigger?: string; action?: string; monitor_seconds?: number } | string;
  follow_up_actions: string[];
  mitre_technique: string | null;
  mitre_tactic: string | null;
  reasoning_completed_at: string | null;
  reasoning_loading: boolean;
}

interface AgentHealth {
  status: string;
  ids_agent: string;
  dry_run: boolean;
  circuit_breaker?: { is_open: boolean; consecutive_failures: number };
  rate_limiter?: { last_minute: number; total: number };
}

const ACTION_BADGE: Record<string, string> = {
  DROP:   "bg-red-900/60 text-red-400 border-red-700/50",
  ACCEPT: "bg-tc-green/20 text-tc-green border-tc-green/40",
  RETURN: "bg-yellow-900/60 text-yellow-400 border-yellow-700/50",
};

const SOURCE_BADGE: Record<string, string> = {
  agent:  "bg-orange-900/40 text-orange-400 border-orange-700/40",
  sdnc:   "bg-blue-900/40 text-blue-400 border-blue-700/40",
  manual: "bg-tc-card text-tc-text-dim border-tc-border",
};

function extractRules(leafData: LeafData): Rule[] {
  const raw = leafData?.rules;
  if (!raw) return [];
  if (Array.isArray(raw)) return raw as Rule[];
  const robj = raw as Record<string, unknown>;
  const notif = robj?.notification;
  if (Array.isArray(notif) && notif.length > 0) {
    const updates = (notif[0] as Record<string, unknown>)?.update;
    if (Array.isArray(updates)) {
      const rules: Rule[] = [];
      for (const u of updates) {
        const val = (u as Record<string, unknown>)?.val;
        if (val && typeof val === "object" && (val as Record<string, unknown>)["rule-id"])
          rules.push(val as Rule);
      }
      if (rules.length > 0) return rules;
    }
  }
  if (Array.isArray(robj?.rule)) return robj.rule as Rule[];
  return [];
}

function fmtTs(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleDateString("vi-VN", { month: "2-digit", day: "2-digit" })
      + " " + d.toLocaleTimeString("vi-VN", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch { return iso.slice(0, 19).replace("T", " "); }
}

function ConfBar({ v }: { v: number | null }) {
  if (v === null) return <span className="text-tc-text-dim">—</span>;
  const pct = Math.round(v * 100);
  const color = pct >= 90 ? "bg-tc-green" : pct >= 70 ? "bg-yellow-400" : "bg-red-400";
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-12 h-1.5 rounded-full bg-tc-border overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className={`text-xs font-mono ${pct >= 90 ? "text-tc-green" : pct >= 70 ? "text-yellow-400" : "text-red-400"}`}>
        {pct}%
      </span>
    </div>
  );
}

export default function PolicyPage() {
  const [leavesData, setLeavesData]       = useState<Record<string, LeafData>>({});
  const [autoBlock, setAutoBlock]         = useState<{ enabled: boolean; blocked_ip_count?: number } | null>(null);
  const [agentHealth, setAgentHealth]     = useState<AgentHealth | null>(null);
  const [agentDecisions, setDecisions]    = useState<AgentDecision[]>([]);
  const [openDecisionId, setOpenDecisionId] = useState<string | null>(null);
  const [loading, setLoading]             = useState(true);
  const [toggling, setToggling]           = useState(false);
  const [pushStatus, setPushStatus]       = useState<string | null>(null);
  const [deleting, setDeleting]           = useState<string | null>(null);
  const [form, setForm] = useState({
    rule_id: "", action: "DROP", src_ip: "", dst_ip: "",
    protocol: "all", priority: "50", comment: "",
  });

  const loadRules = useCallback(async () => {
    try {
      const d = await (await fetch("/api/ids/rules", { cache: "no-store" })).json();
      if (d?.leaves) setLeavesData(d.leaves);
    } catch { /* sf offline */ } finally { setLoading(false); }
  }, []);

  const loadAutoBlock = useCallback(async () => {
    try { setAutoBlock(await (await fetch("/api/ids/autoblock", { cache: "no-store" })).json()); }
    catch { setAutoBlock({ enabled: false }); }
  }, []);

  const loadAgent = useCallback(async () => {
    try {
      const [h, d] = await Promise.all([
        fetch("/api/intel/health",    { cache: "no-store" }).then(r => r.ok ? r.json() : null),
        fetch("/api/intel/decisions", { cache: "no-store" }).then(r => r.ok ? r.json() : []),
      ]);
      if (h) setAgentHealth(h);
      if (Array.isArray(d)) setDecisions(d);
    } catch { /* offline */ }
  }, []);

  useEffect(() => {
    loadRules(); loadAutoBlock(); loadAgent();
    const t = setInterval(() => { loadRules(); loadAutoBlock(); loadAgent(); }, 8000);
    return () => clearInterval(t);
  }, [loadRules, loadAutoBlock, loadAgent]);

  const toggleAutoBlock = async () => {
    if (!autoBlock) return;
    setToggling(true);
    try {
      const d = await (await fetch("/api/ids/autoblock", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enable: !autoBlock.enabled }),
      })).json();
      setAutoBlock(p => ({ ...p, enabled: d.enabled ?? !autoBlock.enabled }));
    } finally { setToggling(false); }
  };

  const pushRule = async () => {
    if (!form.rule_id || !form.src_ip) { setPushStatus("error: rule_id và src_ip bắt buộc"); return; }
    setPushStatus("đang push...");
    try {
      const d = await (await fetch("/api/ids/rules", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...form, source: "manual", priority: parseInt(form.priority) || 1000 }),
      })).json();
      if (d.success || d.rule_id) {
        setPushStatus(`✓ pushed to ${d.pushed_to?.join(", ") ?? "LEAF"}`);
        setForm({ rule_id: "", action: "DROP", src_ip: "", dst_ip: "", protocol: "all", priority: "50", comment: "" });
        setTimeout(loadRules, 1000);
      } else { setPushStatus(`error: ${d.error ?? JSON.stringify(d)}`); }
    } catch (e) { setPushStatus(`error: ${e}`); }
    setTimeout(() => setPushStatus(null), 5000);
  };

  const deleteRule = async (rule: Rule) => {
    const id = rule["rule-id"];
    const src = rule["src-prefix"] ?? rule["src-ip"] ?? "*";
    const dst = rule["dst-prefix"] ?? rule["dst-ip"] ?? "*";
    const dport = rule["dst-port"] ?? "*";
    const summary = `${rule.action} ${src} → ${dst}:${dport}`;
    const ok = window.confirm(
      `Xoá rule này?\n\n` +
      `  ID:     ${id}\n` +
      `  Action: ${summary}\n` +
      `  Source: ${rule.source ?? "manual"}\n\n` +
      `Hành động này không thể hoàn tác.`
    );
    if (!ok) return;

    setDeleting(id);
    try {
      const d = await (await fetch(`/api/ids/rules/${encodeURIComponent(id)}`, { method: "DELETE" })).json();
      if (d.success) setTimeout(loadRules, 800);
    } finally { setDeleting(null); }
  };

  // Aggregate rules
  const allRules: Array<Rule & { _leaf: string }> = [];
  const seen = new Set<string>();
  for (const [leaf, ld] of Object.entries(leavesData)) {
    for (const r of extractRules(ld)) {
      const id = r["rule-id"];
      if (!seen.has(id)) { seen.add(id); allRules.push({ ...r, _leaf: leaf }); }
    }
  }
  const connectedLeaves = Object.values(leavesData).filter(l => l.connected).length;
  const isDryRun = agentHealth?.dry_run ?? true;
  const cbOpen   = agentHealth?.circuit_breaker?.is_open ?? false;

  const inputCls = "rounded-lg border border-tc-border bg-tc-darker px-3 py-2 text-sm font-mono text-white placeholder:text-tc-text-dim focus:border-tc-green/60 focus:outline-none";

  return (
    <main className="min-h-screen bg-tc-darker pt-20">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 py-8 space-y-6">

        {/* ── Header ─────────────────────────────────────────────── */}
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold text-white font-mono">Policy Manager</h1>
          <span className={`flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-mono border ${
            connectedLeaves > 0 ? "bg-tc-green/10 text-tc-green border-tc-green/30" : "bg-red-900/20 text-red-400 border-red-700/30"
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full ${connectedLeaves > 0 ? "bg-tc-green animate-pulse" : "bg-red-400"}`} />
            {connectedLeaves > 0 ? `${connectedLeaves} LEAF` : "SF offline"}
          </span>
        </div>

        {/* ── Stats row ──────────────────────────────────────────── */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className={`rounded-xl border px-4 py-3 flex flex-col gap-2 ${
            autoBlock?.enabled ? "border-tc-green/40 bg-tc-green/5" : "border-tc-border bg-tc-card"
          }`}>
            <div className="text-xs text-tc-text-dim font-mono">Auto-Block</div>
            <div className={`text-lg font-bold font-mono ${autoBlock?.enabled ? "text-tc-green" : "text-tc-text-dim"}`}>
              {autoBlock?.enabled ? "ENABLED" : "DISABLED"}
            </div>
            <button onClick={toggleAutoBlock} disabled={toggling || !autoBlock}
              className={`rounded border px-2 py-1 text-xs font-mono font-bold transition-all disabled:opacity-50 ${
                autoBlock?.enabled ? "border-red-700/50 text-red-400 hover:bg-red-900/20" : "border-tc-green/40 text-tc-green hover:bg-tc-green/10"
              }`}>
              {toggling ? "..." : autoBlock?.enabled ? "Disable" : "Enable"}
            </button>
          </div>
          <div className="rounded-xl border border-tc-border bg-tc-card px-4 py-3 text-center">
            <div className="text-xl font-bold font-mono text-white">{loading ? "…" : allRules.length}</div>
            <div className="text-xs text-tc-text-dim mt-1">Total Rules</div>
          </div>
          <div className="rounded-xl border border-tc-border bg-tc-card px-4 py-3 text-center">
            <div className="text-xl font-bold font-mono text-red-400">{allRules.filter(r => r.action === "DROP").length}</div>
            <div className="text-xs text-tc-text-dim mt-1">DROP</div>
          </div>
          <div className="rounded-xl border border-tc-border bg-tc-card px-4 py-3 text-center">
            <div className="text-xl font-bold font-mono text-tc-green">{allRules.filter(r => r.action === "ACCEPT").length}</div>
            <div className="text-xs text-tc-text-dim mt-1">ACCEPT</div>
          </div>
        </div>

        {/* ── AI Agent status bar ────────────────────────────────── */}
        <div className={`rounded-xl border px-4 py-3 flex items-center justify-between flex-wrap gap-3 ${
          cbOpen ? "border-red-700/50 bg-red-900/10" :
          !isDryRun ? "border-orange-600/40 bg-orange-900/5" :
          "border-yellow-700/40 bg-yellow-900/5"
        }`}>
          <div className="flex items-center gap-3">
            <div className={`w-2 h-2 rounded-full ${cbOpen ? "bg-red-400 animate-pulse" : "bg-orange-400 animate-pulse"}`} />
            <span className="text-sm font-bold font-mono text-white">AI Agent</span>
            <span className={`px-2 py-0.5 rounded border text-xs font-mono font-bold ${
              cbOpen ? "border-red-700/50 text-red-400 bg-red-900/20" :
              !isDryRun ? "border-orange-600/50 text-orange-300 bg-orange-900/20" :
              "border-yellow-700/50 text-yellow-400 bg-yellow-900/20"
            }`}>
              {cbOpen ? "CIRCUIT OPEN ⚠" : !isDryRun ? "LIVE ENFORCEMENT" : "DRY-RUN"}
            </span>
          </div>
          <div className="flex items-center gap-4 text-xs font-mono text-tc-text-dim">
            {agentHealth?.rate_limiter && <span>rules pushed: {agentHealth.rate_limiter.total}</span>}
            <span className={agentHealth?.ids_agent === "connected" ? "text-tc-green" : "text-red-400"}>
              IDS {agentHealth?.ids_agent ?? "offline"}
            </span>
          </div>
        </div>

        {/* ── Push rule form ─────────────────────────────────────── */}
        <div className="rounded-xl border border-tc-border bg-tc-card p-5">
          <h2 className="text-sm font-bold font-mono text-white mb-4">Push New Rule</h2>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mb-3">
            <input className={`${inputCls} col-span-2 sm:col-span-1`} placeholder="rule-id"
              value={form.rule_id} onChange={e => setForm(f => ({ ...f, rule_id: e.target.value }))} />
            <select className={inputCls} value={form.action} onChange={e => setForm(f => ({ ...f, action: e.target.value }))}>
              <option value="DROP">DROP</option><option value="ACCEPT">ACCEPT</option><option value="RETURN">RETURN</option>
            </select>
            <input className={inputCls} placeholder="src-ip (CIDR)" value={form.src_ip}
              onChange={e => setForm(f => ({ ...f, src_ip: e.target.value }))} />
            <input className={inputCls} placeholder="dst-ip (optional)" value={form.dst_ip}
              onChange={e => setForm(f => ({ ...f, dst_ip: e.target.value }))} />
            <input className={`${inputCls} w-24`} placeholder="priority" type="number" value={form.priority}
              onChange={e => setForm(f => ({ ...f, priority: e.target.value }))} />
          </div>
          <div className="flex gap-3">
            <input className={`${inputCls} flex-1`} placeholder="comment (optional)" value={form.comment}
              onChange={e => setForm(f => ({ ...f, comment: e.target.value }))} />
            <button onClick={pushRule}
              className="rounded-lg border border-tc-green bg-tc-green/10 px-5 py-2 text-sm font-mono font-bold text-tc-green hover:bg-tc-green/20 transition-all whitespace-nowrap">
              Push Rule
            </button>
          </div>
          {pushStatus && (
            <div className={`mt-2 text-xs font-mono ${pushStatus.startsWith("error") ? "text-red-400" : "text-tc-green"}`}>
              {pushStatus}
            </div>
          )}
        </div>

        {/* ── Active Rules ───────────────────────────────────────── */}
        <div className="rounded-xl border border-tc-border bg-tc-card overflow-hidden">
          <div className="border-b border-tc-border px-4 py-3 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-sm font-bold font-mono text-white">Active Rules</span>
              <span className="text-xs font-mono text-tc-text-dim">({allRules.length})</span>
              {allRules.filter(r => r.source === "agent").length > 0 && (
                <span className="px-2 py-0.5 rounded border text-xs font-mono border-orange-700/40 text-orange-400 bg-orange-900/20">
                  {allRules.filter(r => r.source === "agent").length} agent
                </span>
              )}
            </div>
            <button onClick={loadRules}
              className="text-xs font-mono text-tc-text-dim hover:text-tc-green transition-colors border border-tc-border/50 rounded px-2 py-1">
              ↻ Refresh
            </button>
          </div>
          <div className="hidden sm:grid grid-cols-[1fr_80px_160px_140px_80px_80px_60px] gap-2 border-b border-tc-border/50 px-4 py-2 text-xs font-mono text-tc-text-dim">
            <span>Rule ID</span><span>Action</span><span>Src IP</span>
            <span>Comment</span><span>Src</span><span>Priority</span><span></span>
          </div>
          <div className="max-h-72 overflow-y-auto">
            {loading ? (
              <div className="p-6 text-center font-mono text-tc-green text-sm animate-pulse">Querying LEAFs...</div>
            ) : allRules.length === 0 ? (
              <div className="p-6 text-center font-mono text-tc-text-dim text-sm">
                {connectedLeaves === 0 ? "⚠ No LEAF connections" : "No rules active."}
              </div>
            ) : allRules.map(rule => (
              <div key={rule["rule-id"]}
                className={`border-b border-tc-border/30 px-4 py-3 hover:bg-tc-green/5 transition-colors ${rule.source === "agent" ? "bg-orange-900/5" : ""}`}>
                <div className="hidden sm:grid grid-cols-[1fr_80px_160px_140px_80px_80px_60px] gap-2 items-center">
                  <span className="text-xs font-mono text-white truncate">{rule["rule-id"]}</span>
                  <span className={`px-2 py-0.5 rounded border text-xs font-mono font-bold w-fit ${ACTION_BADGE[rule.action] ?? ACTION_BADGE.DROP}`}>
                    {rule.action}
                  </span>
                  <span className="text-xs font-mono text-tc-text-dim">{rule["src-prefix"] ?? rule["src-ip"] ?? "—"}</span>
                  <span className="text-xs text-tc-text-dim truncate">{rule.comment ?? "—"}</span>
                  <span className={`px-1.5 py-0.5 rounded border text-xs font-mono w-fit ${SOURCE_BADGE[rule.source ?? "manual"] ?? SOURCE_BADGE.manual}`}>
                    {rule.source ?? "—"}
                  </span>
                  <span className="text-xs font-mono text-tc-text-dim">{rule.priority ?? "—"}</span>
                  <button onClick={() => deleteRule(rule)} disabled={deleting === rule["rule-id"]}
                    className="text-xs font-mono text-red-400 border border-red-700/40 rounded px-2 py-1 hover:bg-red-900/20 disabled:opacity-50">
                    {deleting === rule["rule-id"] ? "…" : "Del"}
                  </button>
                </div>
                <div className="sm:hidden flex flex-col gap-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-mono text-white truncate">{rule["rule-id"]}</span>
                    <span className={`px-2 py-0.5 rounded border text-xs font-mono font-bold ${ACTION_BADGE[rule.action] ?? ACTION_BADGE.DROP}`}>{rule.action}</span>
                  </div>
                  <button onClick={() => deleteRule(rule)} disabled={deleting === rule["rule-id"]}
                    className="text-xs font-mono text-red-400 border border-red-700/40 rounded px-2 py-0.5 hover:bg-red-900/20 w-fit">
                    {deleting === rule["rule-id"] ? "..." : "Delete"}
                  </button>
                </div>
              </div>
            ))}
          </div>
          <div className="border-t border-tc-border/50 px-4 py-2 flex flex-wrap gap-2">
            {Object.entries(leavesData).map(([name, leaf]) => (
              <span key={name} className={`flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-mono border ${
                leaf.connected ? "border-tc-green/30 text-tc-green" : "border-red-700/30 text-red-400"
              }`}>
                <span className={`w-1.5 h-1.5 rounded-full ${leaf.connected ? "bg-tc-green" : "bg-red-400"}`} />
                {name} · {extractRules(leaf).length} rules
              </span>
            ))}
          </div>
        </div>

        {/* ── Agent Policy History ───────────────────────────────── */}
        <div className="rounded-xl border border-tc-border bg-tc-card overflow-hidden">
          <div className="border-b border-tc-border px-4 py-3 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-sm font-bold font-mono text-white">Agent Policy History</span>
              {agentDecisions.length > 0 && (
                <span className="px-2 py-0.5 rounded border text-xs font-mono border-tc-green/30 text-tc-green bg-tc-green/10">
                  {agentDecisions.length} decisions
                </span>
              )}
            </div>
            <div className="flex items-center gap-2 text-xs font-mono text-tc-text-dim">
              {!isDryRun && <span className="text-orange-400">● LIVE</span>}
              {isDryRun  && <span className="text-yellow-500">● DRY-RUN</span>}
              <button onClick={loadAgent}
                className="border border-tc-border/50 rounded px-2 py-1 hover:text-tc-green transition-colors">
                ↻
              </button>
            </div>
          </div>

          {agentDecisions.length === 0 ? (
            <div className="p-8 text-center font-mono text-tc-text-dim text-sm">
              {agentHealth === null
                ? "⚠ Intelligence layer offline — không kết nối được localhost:8767"
                : "Chưa có quyết định nào — chạy thực nghiệm hoặc trigger alert để xem"}
            </div>
          ) : (
            <>
              {/* Header row */}
              <div className="hidden sm:grid grid-cols-[150px_90px_70px_140px_1fr_90px_80px_60px] gap-3 border-b border-tc-border/50 px-4 py-2 text-xs font-mono text-tc-text-dim uppercase tracking-wide">
                <span>Thời điểm</span>
                <span>Quyết định</span>
                <span>SID</span>
                <span>Attacker IP</span>
                <span>Rule được push</span>
                <span>Confidence</span>
                <span>Latency</span>
                <span>Detail</span>
              </div>

              <div className="max-h-96 overflow-y-auto divide-y divide-tc-border/20">
                {agentDecisions.map((d, i) => (
                  <div key={d.id}
                    className={`px-4 py-3 hover:bg-white/5 transition-colors ${
                      i === 0 ? "bg-orange-900/10" : ""
                    } ${d.decision === "enforced" ? "border-l-2 border-l-red-500/60" : "border-l-2 border-l-yellow-600/40"}`}>

                    {/* Desktop */}
                    <div className="hidden sm:grid grid-cols-[150px_90px_70px_140px_1fr_90px_80px_60px] gap-3 items-center">
                      <span className="text-xs font-mono text-tc-text-dim">{fmtTs(d.timestamp)}</span>

                      <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold border w-fit ${
                        d.decision === "enforced"
                          ? "border-red-600/60 text-red-400 bg-red-900/25"
                          : "border-yellow-600/40 text-yellow-400 bg-yellow-900/15"
                      }`}>
                        {d.decision === "enforced" ? "⚡ ENFORCED" : "◎ DRY-RUN"}
                      </span>

                      <span className="text-xs font-mono text-white">#{d.alert_sid}</span>

                      <span className="text-xs font-mono text-orange-300 truncate">{d.attacker_ip}</span>

                      <div className="text-xs font-mono truncate">
                        {d.action && d.block_src ? (
                          <span>
                            <span className="text-red-400 font-bold">{d.action}</span>
                            <span className="text-tc-text-dim"> {d.block_src}</span>
                            {d.block_dst && <span className="text-tc-text-dim"> → {d.block_dst}</span>}
                          </span>
                        ) : d.action ? (
                          <span className="text-tc-text-dim">{d.action}</span>
                        ) : (
                          <span className="text-tc-text-dim italic">intent pending fix</span>
                        )}
                      </div>

                      <ConfBar v={d.confidence} />

                      <span className="text-xs font-mono text-tc-text-dim">{d.latency_ms.toFixed(0)} ms</span>

                      <button
                        onClick={() => setOpenDecisionId(d.id)}
                        title="Show agent reasoning"
                        aria-label="Show agent reasoning"
                        className="inline-flex items-center justify-center h-7 w-7 rounded border border-tc-border/40 text-tc-text-dim hover:border-tc-green/60 hover:text-tc-green hover:bg-tc-green/5 transition-colors">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                          <path d="M9 18h6"/>
                          <path d="M10 22h4"/>
                          <path d="M15.09 14c.18-.98.65-1.74 1.41-2.5A4.65 4.65 0 0 0 18 8 6 6 0 0 0 6 8c0 1 .23 2.23 1.5 3.5A4.61 4.61 0 0 1 8.91 14"/>
                        </svg>
                      </button>
                    </div>

                    {/* Mobile */}
                    <div className="sm:hidden space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-mono text-tc-text-dim">{fmtTs(d.timestamp)}</span>
                        <span className={`px-2 py-0.5 rounded border text-xs font-mono font-bold ${
                          d.decision === "enforced" ? "border-red-600/60 text-red-400" : "border-yellow-600/40 text-yellow-400"
                        }`}>
                          {d.decision === "enforced" ? "ENFORCED" : "DRY-RUN"}
                        </span>
                      </div>
                      <div className="text-xs font-mono text-white">SID #{d.alert_sid} · {d.attacker_ip}</div>
                      {d.block_src && (
                        <div className="text-xs font-mono text-red-400">{d.action} {d.block_src}</div>
                      )}
                      <ConfBar v={d.confidence} />
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>

      </div>

      {openDecisionId && (
        <ReasoningModal
          decisionId={openDecisionId}
          onClose={() => setOpenDecisionId(null)}
        />
      )}
    </main>
  );
}

// ── Reasoning modal ──────────────────────────────────────────────────────────
function ReasoningModal({
  decisionId,
  onClose,
}: {
  decisionId: string;
  onClose: () => void;
}) {
  const [detail, setDetail] = useState<DecisionDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    let pollTimer: ReturnType<typeof setTimeout> | null = null;

    const fetchDetail = async () => {
      try {
        const res = await fetch(`/api/intel/decisions/${decisionId}`, { cache: "no-store" });
        if (!res.ok) {
          setError(`HTTP ${res.status}`);
          return;
        }
        const data = (await res.json()) as DecisionDetail;
        if (cancelled) return;
        setDetail(data);
        // Auto-poll while reasoning is still loading (Stage 2 LLM call running)
        if (data.reasoning_loading) {
          pollTimer = setTimeout(fetchDetail, 2000);
        }
      } catch (e) {
        setError(String(e));
      }
    };
    fetchDetail();

    const onEsc = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onEsc);
    return () => {
      cancelled = true;
      if (pollTimer) clearTimeout(pollTimer);
      window.removeEventListener("keydown", onEsc);
    };
  }, [decisionId, onClose]);

  const langfuseUrl = detail?.trace_id
    ? `http://localhost:3001/trace/${detail.trace_id}`
    : null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4"
      onClick={onClose}
    >
      <div
        className="bg-tc-card border border-tc-border rounded-xl max-w-3xl w-full max-h-[85vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="sticky top-0 bg-tc-card border-b border-tc-border px-5 py-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-tc-green" aria-hidden="true">
              <path d="M9 18h6"/>
              <path d="M10 22h4"/>
              <path d="M15.09 14c.18-.98.65-1.74 1.41-2.5A4.65 4.65 0 0 0 18 8 6 6 0 0 0 6 8c0 1 .23 2.23 1.5 3.5A4.61 4.61 0 0 1 8.91 14"/>
            </svg>
            <span className="text-sm font-bold font-mono text-white">Agent Reasoning</span>
            {detail?.reasoning_loading && (
              <span className="text-xs font-mono text-yellow-400 ml-2">loading reasoning...</span>
            )}
          </div>
          <div className="flex items-center gap-2">
            {langfuseUrl && (
              <a
                href={langfuseUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs font-mono px-2 py-1 rounded border border-tc-border/50 hover:text-tc-green hover:border-tc-green/50 transition-colors"
                title="Open Langfuse trace"
              >
                📊 Trace
              </a>
            )}
            <button
              onClick={onClose}
              className="text-xs font-mono px-2 py-1 rounded border border-tc-border/50 hover:text-red-400 hover:border-red-500/50 transition-colors"
            >
              ✕ Close
            </button>
          </div>
        </div>

        <div className="p-5 space-y-4 font-mono text-sm">
          {error && (
            <div className="text-red-400 text-xs">Error loading decision: {error}</div>
          )}
          {!detail && !error && (
            <div className="text-tc-text-dim text-xs">Loading...</div>
          )}
          {detail && (
            <>
              {/* Header */}
              <div className="grid grid-cols-2 gap-3 text-xs border-b border-tc-border/30 pb-3">
                <div><span className="text-tc-text-dim">Decision ID:</span> <span className="text-white">{detail.id.slice(0, 8)}...</span></div>
                <div><span className="text-tc-text-dim">SID:</span> <span className="text-white">#{detail.alert_sid}</span></div>
                <div><span className="text-tc-text-dim">Outcome:</span> <span className={detail.outcome === "enforced" ? "text-red-400" : "text-yellow-400"}>{detail.outcome.toUpperCase()}</span></div>
                <div><span className="text-tc-text-dim">Confidence:</span> <span className="text-white">{detail.confidence !== null ? (detail.confidence * 100).toFixed(0) + "%" : "—"}</span></div>
                <div><span className="text-tc-text-dim">Action:</span> <span className="text-red-400 font-bold">{detail.action ?? "—"}</span></div>
                <div><span className="text-tc-text-dim">Latency:</span> <span className="text-white">{detail.latency_ms.toFixed(0)} ms</span></div>
                <div className="col-span-2"><span className="text-tc-text-dim">Rule:</span> <span className="text-orange-300">{detail.src_ip ?? "—"} → {detail.dst_ip || "(any)"}{detail.dst_port ? `:${detail.dst_port}` : ""}</span></div>
                {detail.rule_id && <div className="col-span-2"><span className="text-tc-text-dim">Rule ID:</span> <span className="text-orange-300">{detail.rule_id}</span> <span className="text-tc-text-dim">(TTL {detail.ttl_seconds}s)</span></div>}
              </div>

              {detail.reasoning_loading ? (
                <div className="text-yellow-400 text-xs italic">
                  Stage 2 reasoning trace is being generated by the LLM. Polling every 2s...
                </div>
              ) : detail.reasoning.length === 0 && !detail.primary_hypothesis ? (
                <div className="text-tc-text-dim text-xs italic">
                  Reasoning trace unavailable for this decision (Stage 2 LLM call did not complete).
                  The decision was enforced based on policy fields only.
                </div>
              ) : (
                <>
                  {/* Primary hypothesis */}
                  {detail.primary_hypothesis && (
                    <Section title="Primary hypothesis">
                      <div className="text-orange-300">{detail.primary_hypothesis}</div>
                    </Section>
                  )}

                  {/* Hypotheses */}
                  {detail.hypotheses.length > 0 && (
                    <Section title={`Hypotheses considered (${detail.hypotheses.length})`}>
                      <ul className="space-y-1.5 text-xs">
                        {detail.hypotheses.map((h, i) => (
                          <li key={i} className="text-tc-text-dim">
                            <span className="text-tc-green">●</span>{" "}
                            <span className="text-white">{typeof h === "string" ? h : (h.description || h.name)}</span>
                          </li>
                        ))}
                      </ul>
                    </Section>
                  )}

                  {/* Reasoning steps */}
                  {detail.reasoning.length > 0 && (
                    <Section title={`Reasoning steps (${detail.reasoning.length})`}>
                      <ol className="space-y-1.5 text-xs list-decimal list-inside">
                        {detail.reasoning.map((s, i) => (
                          <li key={i} className="text-white">{s}</li>
                        ))}
                      </ol>
                    </Section>
                  )}

                  {/* Alternatives */}
                  {detail.alternative_actions.length > 0 && (
                    <Section title="Alternative actions (Plan B)">
                      <ul className="space-y-1 text-xs">
                        {detail.alternative_actions.map((a, i) => (
                          <li key={i} className="text-tc-text-dim">
                            • {typeof a === "string" ? a : (a.rationale || a.trigger_condition || JSON.stringify(a))}
                          </li>
                        ))}
                      </ul>
                    </Section>
                  )}

                  {/* Rollback */}
                  {(detail.rollback_plan && (typeof detail.rollback_plan === "string" || (detail.rollback_plan.action || detail.rollback_plan.trigger))) && (
                    <Section title="Rollback plan">
                      <div className="text-xs text-yellow-300">
                        {typeof detail.rollback_plan === "string"
                          ? detail.rollback_plan
                          : `Trigger: ${detail.rollback_plan.trigger || "—"}. Action: ${detail.rollback_plan.action || "—"}. Monitor ${detail.rollback_plan.monitor_seconds || 300}s.`}
                      </div>
                    </Section>
                  )}

                  {/* Follow-up */}
                  {detail.follow_up_actions.length > 0 && (
                    <Section title="Follow-up monitoring">
                      <ul className="space-y-1 text-xs">
                        {detail.follow_up_actions.map((f, i) => (
                          <li key={i} className="text-tc-text-dim">→ {f}</li>
                        ))}
                      </ul>
                    </Section>
                  )}

                  {/* MITRE */}
                  {(detail.mitre_technique || detail.mitre_tactic) && (
                    <Section title="MITRE ATT&CK">
                      <div className="text-xs">
                        {detail.mitre_tactic && <span className="text-blue-300 mr-3">Tactic: {detail.mitre_tactic}</span>}
                        {detail.mitre_technique && <span className="text-blue-300">Technique: {detail.mitre_technique}</span>}
                      </div>
                    </Section>
                  )}
                </>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wide text-tc-text-dim mb-1.5 border-b border-tc-border/20 pb-1">{title}</div>
      <div>{children}</div>
    </div>
  );
}
