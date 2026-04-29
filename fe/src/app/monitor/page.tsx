"use client";

import { useEffect, useRef, useState } from "react";

interface Alert {
  timestamp: string;
  alert: {
    signature: string;
    signature_id: number;
    severity: number;
    category: string;
  };
  src_ip: string;
  dest_ip: string;
  proto: string;
}

const PRIORITY_COLORS: Record<number, string> = {
  1: "border-l-red-500 bg-red-950/20",
  2: "border-l-orange-500 bg-orange-950/20",
  3: "border-l-yellow-500 bg-yellow-950/10",
  4: "border-l-tc-border bg-transparent",
};

const PRIORITY_BADGE: Record<number, string> = {
  1: "bg-red-900/60 text-red-400 border-red-700/50",
  2: "bg-orange-900/60 text-orange-400 border-orange-700/50",
  3: "bg-yellow-900/60 text-yellow-400 border-yellow-700/50",
  4: "bg-tc-card text-tc-text-dim border-tc-border",
};

const PRIORITY_LABEL: Record<number, string> = {
  1: "P1 CRITICAL",
  2: "P2 HIGH",
  3: "P3 INFO",
  4: "P4 AUDIT",
};

const ZONES = ["ALL", "WEB", "DB", "APP", "MGT"] as const;
type Zone = (typeof ZONES)[number];
type Priority = 0 | 1 | 2 | 3 | 4;


function ipZone(ip: string): string {
  if (ip.startsWith("10.1.100.")) return "WEB";
  if (ip.startsWith("10.1.200.")) return "DB";
  if (ip.startsWith("10.2.100.")) return "APP";
  if (ip.startsWith("10.2.50.")) return "MGT";
  return "—";
}

function formatTs(ts: string) {
  try {
    return new Date(ts).toLocaleString("vi-VN", { hour12: false });
  } catch {
    return ts;
  }
}

export default function MonitorPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [paused, setPaused] = useState(false);
  const [status, setStatus] = useState<"connecting" | "live" | "offline">("connecting");
  const [filterZone, setFilterZone] = useState<Zone>("ALL");
  const [filterPriority, setFilterPriority] = useState<Priority>(0);
  const [loading, setLoading] = useState(true);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const [mounted, setMounted] = useState(false);

  const pausedRef = useRef(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => { setMounted(true); }, []);

  // Load historical alerts on mount
  useEffect(() => {
    fetch("/api/ids/alerts?last=200")
      .then((r) => r.json())
      .then((json) => {
        const data: Alert[] = Array.isArray(json) ? json : (json.alerts ?? []);
        setAlerts([...data].reverse());
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  // SSE real-time stream — qua Next.js /api/ids/stream (browser chỉ cần port 3000)
  useEffect(() => {
    let es: EventSource;
    let reconnectTimer: ReturnType<typeof setTimeout>;

    const connect = () => {
      es = new EventSource("/api/ids/stream");

      es.onopen = () => {
        setStatus("live");
        setLastUpdate(new Date());
      };
      es.onerror = () => {
        setStatus("offline");
        es.close();
        reconnectTimer = setTimeout(connect, 3000);
      };
      es.onmessage = (evt) => {
        try {
          const data = JSON.parse(evt.data);
          // Event "connected" từ Go Agent — xác nhận stream live
          if (data?.type === "connected") {
            setStatus("live");
            setLastUpdate(new Date());
            return;
          }
          if (pausedRef.current) return;
          if (!data?.alert?.signature) return;
          setStatus("live");
          setAlerts((prev) => [data as Alert, ...prev].slice(0, 500));
          setLastUpdate(new Date());
        } catch {}
      };
    };

    connect();
    return () => {
      clearTimeout(reconnectTimer);
      es?.close();
    };
  }, []);

  useEffect(() => {
    if (!paused) {
      bottomRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [alerts.length, paused]);

  const togglePause = () => {
    setPaused((p) => {
      pausedRef.current = !p;
      return !p;
    });
  };

  const filtered = alerts.filter((a) => {
    if (filterZone !== "ALL" && ipZone(a.src_ip) !== filterZone) return false;
    if (filterPriority !== 0 && a.alert?.severity !== filterPriority) return false;
    return true;
  });

  const stats = {
    total: alerts.length,
    p1: alerts.filter((a) => a.alert?.severity === 1).length,
    p2: alerts.filter((a) => a.alert?.severity === 2).length,
    p3: alerts.filter((a) => a.alert?.severity === 3).length,
    p4: alerts.filter((a) => a.alert?.severity === 4).length,
  };

  return (
    <main className="min-h-screen bg-tc-darker pt-20">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 py-8">

        {/* Header */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-8">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <h1 className="text-2xl font-bold text-white font-mono">Live Monitor</h1>
              {mounted && (
                <span className={`flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-mono border ${
                  status === "connecting"
                    ? "bg-tc-card text-tc-text-dim border-tc-border"
                    : status === "live"
                    ? "bg-tc-green/10 text-tc-green border-tc-green/30"
                    : "bg-red-900/20 text-red-400 border-red-700/30"
                }`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${
                    status === "connecting" ? "bg-tc-text-dim" :
                    status === "live" ? "bg-tc-green animate-pulse" : "bg-red-400"
                  }`} />
                  {status === "connecting" ? "CONNECTING" : status === "live" ? "LIVE" : "OFFLINE"}
                </span>
              )}
              {mounted && lastUpdate && (
                <span className="text-xs font-mono text-tc-text-dim">
                  {lastUpdate.toLocaleTimeString("vi-VN", { hour12: false })}
                </span>
              )}
            </div>
            <p className="text-sm text-tc-text-dim">
              SSE real-time stream · Go IDS Agent · auto-reconnect on disconnect
            </p>
          </div>
          <button
            onClick={togglePause}
            className={`rounded-lg border px-4 py-2 text-sm font-mono font-bold transition-all ${
              paused
                ? "border-tc-green bg-tc-green/10 text-tc-green hover:bg-tc-green/20"
                : "border-tc-border text-tc-text-dim hover:border-tc-green/30 hover:text-tc-green"
            }`}
          >
            {paused ? "▶ Resume" : "⏸ Pause"}
          </button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-6">
          {[
            { label: "Total", value: stats.total, color: "text-white" },
            { label: "P1 Critical", value: stats.p1, color: "text-red-400" },
            { label: "P2 High", value: stats.p2, color: "text-orange-400" },
            { label: "P3 Info", value: stats.p3, color: "text-yellow-400" },
            { label: "P4 Audit", value: stats.p4, color: "text-tc-text-dim" },
          ].map((s) => (
            <div key={s.label} className="rounded-xl border border-tc-border bg-tc-card px-4 py-3 text-center">
              <div className={`text-xl font-bold font-mono ${s.color}`}>{s.value}</div>
              <div className="text-xs text-tc-text-dim mt-1">{s.label}</div>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div className="flex flex-wrap gap-3 mb-4">
          <div className="flex items-center gap-2">
            <span className="text-xs text-tc-text-dim font-mono">Zone:</span>
            <div className="flex gap-1">
              {ZONES.map((z) => (
                <button key={z} onClick={() => setFilterZone(z)}
                  className={`px-3 py-1 rounded text-xs font-mono border transition-all ${
                    filterZone === z
                      ? "bg-tc-green text-black border-tc-green font-bold"
                      : "border-tc-border text-tc-text-dim hover:border-tc-green/30"
                  }`}
                >{z}</button>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-tc-text-dim font-mono">Priority:</span>
            <div className="flex gap-1">
              {([0, 1, 2, 3, 4] as Priority[]).map((p) => (
                <button key={p} onClick={() => setFilterPriority(p)}
                  className={`px-3 py-1 rounded text-xs font-mono border transition-all ${
                    filterPriority === p
                      ? "bg-tc-green text-black border-tc-green font-bold"
                      : "border-tc-border text-tc-text-dim hover:border-tc-green/30"
                  }`}
                >{p === 0 ? "ALL" : `P${p}`}</button>
              ))}
            </div>
          </div>
        </div>

        {/* Alert Table */}
        <div className="rounded-xl border border-tc-border bg-tc-card overflow-hidden">
          <div className="hidden sm:grid grid-cols-[140px_1fr_190px_60px_120px] gap-2 border-b border-tc-border px-4 py-2 text-xs font-mono text-tc-text-dim">
            <span>Time</span><span>Rule</span><span>Src → Dst</span><span>Zone</span><span>Priority</span>
          </div>

          <div className="max-h-[60vh] overflow-y-auto">
            {loading ? (
              <div className="p-8 text-center font-mono text-tc-green text-sm animate-pulse">Loading...</div>
            ) : filtered.length === 0 ? (
              <div className="p-8 text-center font-mono text-tc-text-dim text-sm">
                {status === "offline"
                  ? "⚠ Go IDS Agent offline — chạy: cd /3s-com/ids-agent && ./ids-agent"
                  : "No alerts match current filters."}
              </div>
            ) : (
              filtered.map((a, i) => (
                <div key={i} className={`border-b border-tc-border/40 border-l-2 px-4 py-3 hover:bg-tc-green/5 transition-colors ${
                  PRIORITY_COLORS[a.alert?.severity] ?? PRIORITY_COLORS[4]
                }`}>
                  {/* Mobile */}
                  <div className="sm:hidden">
                    <div className="flex items-start justify-between gap-2 mb-1">
                      <span className="text-xs text-tc-text-dim font-mono">{formatTs(a.timestamp)}</span>
                      <span className={`px-2 py-0.5 rounded border text-xs font-mono font-bold ${PRIORITY_BADGE[a.alert?.severity] ?? PRIORITY_BADGE[4]}`}>
                        {PRIORITY_LABEL[a.alert?.severity] ?? `P${a.alert?.severity}`}
                      </span>
                    </div>
                    <div className="text-xs text-tc-text mb-1">{a.alert?.signature}</div>
                    <div className="text-xs font-mono text-tc-text-dim">
                      {a.src_ip} → {a.dest_ip}
                      <span className="ml-2 text-tc-green">[{ipZone(a.src_ip)}]</span>
                    </div>
                  </div>
                  {/* Desktop */}
                  <div className="hidden sm:grid grid-cols-[140px_1fr_190px_60px_120px] gap-2 items-center">
                    <span className="text-xs font-mono text-tc-text-dim whitespace-nowrap truncate">{formatTs(a.timestamp)}</span>
                    <span className="text-xs text-tc-text truncate">{a.alert?.signature}</span>
                    <span className="text-xs font-mono text-tc-text-dim whitespace-nowrap truncate">{a.src_ip} → {a.dest_ip}</span>
                    <span className="text-xs font-mono text-tc-green">{ipZone(a.src_ip)}</span>
                    <span className={`px-2 py-0.5 rounded border text-xs font-mono font-bold w-fit ${PRIORITY_BADGE[a.alert?.severity] ?? PRIORITY_BADGE[4]}`}>
                      {PRIORITY_LABEL[a.alert?.severity] ?? `P${a.alert?.severity}`}
                    </span>
                  </div>
                </div>
              ))
            )}
            <div ref={bottomRef} />
          </div>
        </div>

        <p className="mt-3 text-xs text-tc-text-dim font-mono text-right">
          Showing {filtered.length} of {alerts.length} alerts
        </p>
      </div>
    </main>
  );
}
