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

  const deleteRule = async (id: string) => {
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
                  <button onClick={() => deleteRule(rule["rule-id"])} disabled={deleting === rule["rule-id"]}
                    className="text-xs font-mono text-red-400 border border-red-700/40 rounded px-2 py-1 hover:bg-red-900/20 disabled:opacity-50">
                    {deleting === rule["rule-id"] ? "…" : "Del"}
                  </button>
                </div>
                <div className="sm:hidden flex flex-col gap-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-mono text-white truncate">{rule["rule-id"]}</span>
                    <span className={`px-2 py-0.5 rounded border text-xs font-mono font-bold ${ACTION_BADGE[rule.action] ?? ACTION_BADGE.DROP}`}>{rule.action}</span>
                  </div>
                  <button onClick={() => deleteRule(rule["rule-id"])} disabled={deleting === rule["rule-id"]}
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
              <div className="hidden sm:grid grid-cols-[150px_90px_70px_140px_1fr_90px_80px] gap-3 border-b border-tc-border/50 px-4 py-2 text-xs font-mono text-tc-text-dim uppercase tracking-wide">
                <span>Thời điểm</span>
                <span>Quyết định</span>
                <span>SID</span>
                <span>Attacker IP</span>
                <span>Rule được push</span>
                <span>Confidence</span>
                <span>Latency</span>
              </div>

              <div className="max-h-96 overflow-y-auto divide-y divide-tc-border/20">
                {agentDecisions.map((d, i) => (
                  <div key={d.id}
                    className={`px-4 py-3 hover:bg-white/5 transition-colors ${
                      i === 0 ? "bg-orange-900/10" : ""
                    } ${d.decision === "enforced" ? "border-l-2 border-l-red-500/60" : "border-l-2 border-l-yellow-600/40"}`}>

                    {/* Desktop */}
                    <div className="hidden sm:grid grid-cols-[150px_90px_70px_140px_1fr_90px_80px] gap-3 items-center">
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
    </main>
  );
}
