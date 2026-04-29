"use client";

import { useCallback, useEffect, useState } from "react";

interface Rule {
  "rule-id": string;
  action: "DROP" | "ACCEPT" | "RETURN";
  "src-ip"?: string;
  "src-prefix"?: string;   // bridge returns src-prefix
  "dst-ip"?: string;
  "dst-prefix"?: string;
  protocol?: string;
  "src-port"?: string | number;
  "dst-port"?: string | number;
  priority?: number | string;
  source?: string;
  comment?: string;
  "ttl-seconds"?: number | string;
  chain?: string;
}

interface LeafData {
  connected: boolean;
  rules?: unknown;
  error?: string;
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

// Parse pygnmi response: {notification: [{update: [{path, val}, ...]}]}
// Each update item is a separate rule — extract val from each.
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
        if (val && typeof val === "object" && (val as Record<string, unknown>)["rule-id"]) {
          rules.push(val as Rule);
        }
      }
      if (rules.length > 0) return rules;
    }
  }
  if (Array.isArray(robj?.rule)) return robj.rule as Rule[];
  return [];
}

export default function PolicyPage() {
  const [leavesData, setLeavesData] = useState<Record<string, LeafData>>({});
  const [autoBlock, setAutoBlock] = useState<{ enabled: boolean; blocked_ip_count?: number } | null>(null);
  const [loading, setLoading] = useState(true);
  const [toggling, setToggling] = useState(false);
  const [pushStatus, setPushStatus] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);

  // Form state
  const [form, setForm] = useState({
    rule_id: "", action: "DROP", src_ip: "", dst_ip: "",
    protocol: "all", priority: "50", comment: "",
  });

  const loadRules = useCallback(async () => {
    try {
      const res = await fetch("/api/ids/rules", { cache: "no-store" });
      const data = await res.json();
      if (data?.leaves) setLeavesData(data.leaves);
    } catch {
      // SF unreachable — keep previous state
    } finally {
      setLoading(false);
    }
  }, []);

  const loadAutoBlock = useCallback(async () => {
    try {
      const res = await fetch("/api/ids/autoblock", { cache: "no-store" });
      const data = await res.json();
      setAutoBlock(data);
    } catch {
      setAutoBlock({ enabled: false });
    }
  }, []);

  useEffect(() => {
    loadRules();
    loadAutoBlock();
    const t = setInterval(() => { loadRules(); loadAutoBlock(); }, 10000);
    return () => clearInterval(t);
  }, [loadRules, loadAutoBlock]);

  const toggleAutoBlock = async () => {
    if (!autoBlock) return;
    setToggling(true);
    try {
      const res = await fetch("/api/ids/autoblock", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enable: !autoBlock.enabled }),
      });
      const data = await res.json();
      setAutoBlock((prev) => ({ ...prev, enabled: data.enabled ?? !autoBlock.enabled }));
    } finally {
      setToggling(false);
    }
  };

  const pushRule = async () => {
    if (!form.rule_id || !form.src_ip) {
      setPushStatus("error: rule_id and src_ip are required");
      return;
    }
    setPushStatus("pushing...");
    try {
      const res = await fetch("/api/ids/rules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...form,
          source: "manual",
          priority: parseInt(form.priority) || 1000,
        }),
      });
      const data = await res.json();
      if (data.success || data.rule_id) {
        setPushStatus(`✓ pushed to ${data.pushed_to?.join(", ") ?? "LEAF"}`);
        setForm({ rule_id: "", action: "DROP", src_ip: "", dst_ip: "", protocol: "all", priority: "50", comment: "" });
        setTimeout(loadRules, 1000);
      } else {
        setPushStatus(`error: ${data.error ?? JSON.stringify(data)}`);
      }
    } catch (e) {
      setPushStatus(`error: ${e}`);
    }
    setTimeout(() => setPushStatus(null), 5000);
  };

  const deleteRule = async (ruleId: string) => {
    setDeleting(ruleId);
    try {
      const res = await fetch(`/api/ids/rules/${encodeURIComponent(ruleId)}`, { method: "DELETE" });
      const data = await res.json();
      if (data.success) {
        setTimeout(loadRules, 800);
      }
    } finally {
      setDeleting(null);
    }
  };

  // Aggregate rules from all leaves (deduplicate by rule-id, prefer first occurrence)
  const allRules: Array<Rule & { _leaf: string }> = [];
  const seen = new Set<string>();
  for (const [leafName, leafData] of Object.entries(leavesData)) {
    for (const rule of extractRules(leafData)) {
      const id = rule["rule-id"];
      if (!seen.has(id)) {
        seen.add(id);
        allRules.push({ ...rule, _leaf: leafName });
      }
    }
  }

  const dropCount = allRules.filter((r) => r.action === "DROP").length;
  const acceptCount = allRules.filter((r) => r.action === "ACCEPT").length;
  const connectedLeaves = Object.values(leavesData).filter((l) => l.connected).length;

  const inputCls = "rounded-lg border border-tc-border bg-tc-darker px-3 py-2 text-sm font-mono text-white placeholder:text-tc-text-dim focus:border-tc-green/60 focus:outline-none";

  return (
    <main className="min-h-screen bg-tc-darker pt-20">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 py-8">

        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-1">
            <h1 className="text-2xl font-bold text-white font-mono">Policy Manager</h1>
            <span className={`flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-mono border ${
              connectedLeaves > 0
                ? "bg-tc-green/10 text-tc-green border-tc-green/30"
                : "bg-red-900/20 text-red-400 border-red-700/30"
            }`}>
              <span className={`w-1.5 h-1.5 rounded-full ${connectedLeaves > 0 ? "bg-tc-green animate-pulse" : "bg-red-400"}`} />
              {connectedLeaves > 0 ? `${connectedLeaves} LEAF connected` : "SF offline"}
            </span>
          </div>
          <p className="text-sm text-tc-text-dim">NETCONF → gNMI → iptables · Secure Framework enforcement layer</p>
        </div>

        {/* Stats row */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
          {/* Auto-block card */}
          <div className={`rounded-xl border px-4 py-3 flex flex-col gap-2 ${
            autoBlock?.enabled ? "border-tc-green/40 bg-tc-green/5" : "border-tc-border bg-tc-card"
          }`}>
            <div className="text-xs text-tc-text-dim font-mono">Auto-Block</div>
            <div className={`text-lg font-bold font-mono ${autoBlock?.enabled ? "text-tc-green" : "text-tc-text-dim"}`}>
              {autoBlock?.enabled ? "ENABLED" : "DISABLED"}
            </div>
            <button
              onClick={toggleAutoBlock}
              disabled={toggling || autoBlock === null}
              className={`rounded border px-2 py-1 text-xs font-mono font-bold transition-all disabled:opacity-50 ${
                autoBlock?.enabled
                  ? "border-red-700/50 text-red-400 hover:bg-red-900/20"
                  : "border-tc-green/40 text-tc-green hover:bg-tc-green/10"
              }`}
            >
              {toggling ? "..." : autoBlock?.enabled ? "Disable" : "Enable"}
            </button>
            {autoBlock?.blocked_ip_count !== undefined && (
              <div className="text-xs text-tc-text-dim font-mono">{autoBlock.blocked_ip_count} IPs blocked</div>
            )}
          </div>

          <div className="rounded-xl border border-tc-border bg-tc-card px-4 py-3 text-center">
            <div className="text-xl font-bold font-mono text-white">{loading ? "…" : allRules.length}</div>
            <div className="text-xs text-tc-text-dim mt-1">Total Rules</div>
          </div>
          <div className="rounded-xl border border-tc-border bg-tc-card px-4 py-3 text-center">
            <div className="text-xl font-bold font-mono text-red-400">{loading ? "…" : dropCount}</div>
            <div className="text-xs text-tc-text-dim mt-1">DROP</div>
          </div>
          <div className="rounded-xl border border-tc-border bg-tc-card px-4 py-3 text-center">
            <div className="text-xl font-bold font-mono text-tc-green">{loading ? "…" : acceptCount}</div>
            <div className="text-xs text-tc-text-dim mt-1">ACCEPT</div>
          </div>
        </div>

        {/* Push rule form */}
        <div className="rounded-xl border border-tc-border bg-tc-card p-5 mb-6">
          <h2 className="text-sm font-bold font-mono text-white mb-4">Push New Rule</h2>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mb-3">
            <input
              className={`${inputCls} col-span-2 sm:col-span-1`}
              placeholder="rule-id"
              value={form.rule_id}
              onChange={(e) => setForm((f) => ({ ...f, rule_id: e.target.value }))}
            />
            <select
              className={inputCls}
              value={form.action}
              onChange={(e) => setForm((f) => ({ ...f, action: e.target.value }))}
            >
              <option value="DROP">DROP</option>
              <option value="ACCEPT">ACCEPT</option>
              <option value="RETURN">RETURN</option>
            </select>
            <input
              className={inputCls}
              placeholder="src-ip (CIDR)"
              value={form.src_ip}
              onChange={(e) => setForm((f) => ({ ...f, src_ip: e.target.value }))}
            />
            <input
              className={inputCls}
              placeholder="dst-ip (optional)"
              value={form.dst_ip}
              onChange={(e) => setForm((f) => ({ ...f, dst_ip: e.target.value }))}
            />
            <input
              className={`${inputCls} w-24`}
              placeholder="priority"
              type="number"
              value={form.priority}
              onChange={(e) => setForm((f) => ({ ...f, priority: e.target.value }))}
            />
          </div>
          <div className="flex gap-3">
            <input
              className={`${inputCls} flex-1`}
              placeholder="comment (optional)"
              value={form.comment}
              onChange={(e) => setForm((f) => ({ ...f, comment: e.target.value }))}
            />
            <button
              onClick={pushRule}
              className="rounded-lg border border-tc-green bg-tc-green/10 px-5 py-2 text-sm font-mono font-bold text-tc-green hover:bg-tc-green/20 transition-all whitespace-nowrap"
            >
              Push Rule
            </button>
          </div>
          {pushStatus && (
            <div className={`mt-2 text-xs font-mono ${pushStatus.startsWith("error") ? "text-red-400" : "text-tc-green"}`}>
              {pushStatus}
            </div>
          )}
        </div>

        {/* Rules table */}
        <div className="rounded-xl border border-tc-border bg-tc-card overflow-hidden">
          <div className="border-b border-tc-border px-4 py-3 flex items-center justify-between">
            <span className="text-sm font-mono font-bold text-white">Active Rules</span>
            <button
              onClick={loadRules}
              className="text-xs font-mono text-tc-text-dim hover:text-tc-green transition-colors border border-tc-border/50 rounded px-2 py-1"
            >
              ↻ Refresh
            </button>
          </div>

          {/* Column headers */}
          <div className="hidden sm:grid grid-cols-[1fr_80px_160px_120px_80px_80px_60px] gap-2 border-b border-tc-border/50 px-4 py-2 text-xs font-mono text-tc-text-dim">
            <span>Rule ID</span>
            <span>Action</span>
            <span>Src IP</span>
            <span>Comment</span>
            <span>Src</span>
            <span>Priority</span>
            <span></span>
          </div>

          <div className="max-h-[55vh] overflow-y-auto">
            {loading ? (
              <div className="p-8 text-center font-mono text-tc-green text-sm animate-pulse">Querying LEAFs...</div>
            ) : allRules.length === 0 ? (
              <div className="p-8 text-center font-mono text-tc-text-dim text-sm">
                {connectedLeaves === 0 ? "⚠ No LEAF connections — SF offline or bridge unreachable" : "No rules active."}
              </div>
            ) : (
              allRules.map((rule) => (
                <div
                  key={rule["rule-id"]}
                  className="border-b border-tc-border/30 px-4 py-3 hover:bg-tc-green/5 transition-colors"
                >
                  {/* Mobile */}
                  <div className="sm:hidden flex flex-col gap-1">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-mono text-white font-bold truncate">{rule["rule-id"]}</span>
                      <span className={`px-2 py-0.5 rounded border text-xs font-mono font-bold ${ACTION_BADGE[rule.action] ?? ACTION_BADGE.DROP}`}>
                        {rule.action}
                      </span>
                    </div>
                    {(rule["src-prefix"] ?? rule["src-ip"]) && (
                      <span className="text-xs font-mono text-tc-text-dim">{rule["src-prefix"] ?? rule["src-ip"]}</span>
                    )}
                    {rule.comment && (
                      <span className="text-xs text-tc-text-dim truncate">{rule.comment}</span>
                    )}
                    <button
                      onClick={() => deleteRule(rule["rule-id"])}
                      disabled={deleting === rule["rule-id"]}
                      className="text-xs font-mono text-red-400 border border-red-700/40 rounded px-2 py-0.5 hover:bg-red-900/20 w-fit disabled:opacity-50"
                    >
                      {deleting === rule["rule-id"] ? "..." : "Delete"}
                    </button>
                  </div>

                  {/* Desktop */}
                  <div className="hidden sm:grid grid-cols-[1fr_80px_160px_120px_80px_80px_60px] gap-2 items-center">
                    <span className="text-xs font-mono text-white truncate">{rule["rule-id"]}</span>
                    <span className={`px-2 py-0.5 rounded border text-xs font-mono font-bold w-fit ${ACTION_BADGE[rule.action] ?? ACTION_BADGE.DROP}`}>
                      {rule.action}
                    </span>
                    <span className="text-xs font-mono text-tc-text-dim truncate">{rule["src-prefix"] ?? rule["src-ip"] ?? "—"}</span>
                    <span className="text-xs text-tc-text-dim truncate">{rule.comment ?? "—"}</span>
                    <span className={`px-1.5 py-0.5 rounded border text-xs font-mono w-fit ${SOURCE_BADGE[rule.source ?? "manual"] ?? SOURCE_BADGE.manual}`}>
                      {rule.source ?? "—"}
                    </span>
                    <span className="text-xs font-mono text-tc-text-dim">{rule.priority ?? "—"}</span>
                    <button
                      onClick={() => deleteRule(rule["rule-id"])}
                      disabled={deleting === rule["rule-id"]}
                      className="text-xs font-mono text-red-400 border border-red-700/40 rounded px-2 py-1 hover:bg-red-900/20 disabled:opacity-50 transition-colors"
                    >
                      {deleting === rule["rule-id"] ? "…" : "Del"}
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* LEAF connection status */}
        <div className="mt-4 flex flex-wrap gap-2">
          {Object.entries(leavesData).map(([name, leaf]) => (
            <div key={name} className={`flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-mono border ${
              leaf.connected ? "border-tc-green/30 text-tc-green" : "border-red-700/30 text-red-400"
            }`}>
              <span className={`w-1.5 h-1.5 rounded-full ${leaf.connected ? "bg-tc-green" : "bg-red-400"}`} />
              {name} {leaf.connected ? `· ${extractRules(leaf).length} rules` : "· disconnected"}
            </div>
          ))}
        </div>
      </div>
    </main>
  );
}
