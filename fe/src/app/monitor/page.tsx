"use client";

import { useEffect, useRef, useState } from "react";

// ── Types ──────────────────────────────────────────────────────────────────
interface ViolationEvent {
  kind: "violation";
  timestamp: string;
  alert: { signature: string; signature_id: number; severity: number; category: string };
  src_ip: string; dest_ip: string; proto: string;
}

interface TrafficFlow {
  kind: "flow";
  timestamp: string;
  src_ip: string; src_port: number;
  dest_ip: string; dest_port: number;
  proto: string; app_proto?: string;
  flow?: { bytes_toserver: number; pkts_toserver: number; state: string };
}

interface ServiceStatus {
  service: string; zone: string; dest_ip: string;
  status: "up" | "down" | "unknown"; timestamp: string;
}

type FeedEvent = ViolationEvent | TrafficFlow;

// ── Constants ──────────────────────────────────────────────────────────────
const PRIORITY_ROW: Record<number, string> = {
  1: "border-l-red-500 bg-red-950/20",
  2: "border-l-orange-500 bg-orange-950/20",
  3: "border-l-yellow-500 bg-yellow-950/10",
  4: "border-l-tc-border/60 bg-transparent",
};
const PRIORITY_BADGE: Record<number, string> = {
  1: "bg-red-900/60 text-red-400 border-red-700/50",
  2: "bg-orange-900/60 text-orange-400 border-orange-700/50",
  3: "bg-yellow-900/60 text-yellow-400 border-yellow-700/50",
  4: "bg-tc-card text-tc-text-dim border-tc-border",
};
const PRIORITY_LABEL: Record<number, string> = {
  1: "P1 CRIT", 2: "P2 HIGH", 3: "P3 INFO", 4: "P4 AUDIT",
};
const ZONES = ["ALL", "WEB", "DB", "APP", "MGT"] as const;
type Zone = (typeof ZONES)[number];
type Priority = 0 | 1 | 2 | 3 | 4;

// ── Helpers ────────────────────────────────────────────────────────────────
function ipZone(ip: string): string {
  if (ip?.startsWith("10.1.100.")) return "WEB";
  if (ip?.startsWith("10.1.200.")) return "DB";
  if (ip?.startsWith("10.2.100.")) return "APP";
  if (ip?.startsWith("10.2.50."))  return "MGT";
  return "EXT";
}

function fmtBytes(b?: number) {
  if (!b) return "—";
  if (b < 1024) return `${b}B`;
  return `${(b / 1024).toFixed(1)}KB`;
}

function formatTs(ts: string) {
  try { return new Date(ts).toLocaleString("vi-VN", { hour12: false }); }
  catch { return ts; }
}

function formatTime(ts: string) {
  try { return new Date(ts).toLocaleTimeString("vi-VN", { hour12: false }); }
  catch { return ts; }
}

// ── Component ──────────────────────────────────────────────────────────────
export default function MonitorPage() {
  const [feed, setFeed]         = useState<FeedEvent[]>([]);
  const [services, setServices] = useState<Map<string, ServiceStatus>>(new Map());
  const [connStatus, setConnStatus] = useState<"connecting" | "live" | "offline">("connecting");
  const [filterZone, setFilterZone]         = useState<Zone>("ALL");
  const [filterPriority, setFilterPriority] = useState<Priority>(0);
  const [showFlows, setShowFlows]           = useState(true);
  const [loading, setLoading]   = useState(true);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const [mounted, setMounted]   = useState(false);
  const topRef      = useRef<HTMLDivElement>(null);
  const scrollRef   = useRef<HTMLDivElement>(null);

  useEffect(() => { setMounted(true); }, []);

  // Load history on mount: violations + recent flows
  useEffect(() => {
    const loadViolations = fetch("/api/ids/alerts?last=50")
      .then(r => r.json())
      .then(json => {
        const raw: object[] = Array.isArray(json) ? json : (json.alerts ?? []);
        return raw.map((a: object) => ({ kind: "violation", ...(a as object) } as unknown as ViolationEvent));
      })
      .catch(() => [] as ViolationEvent[]);

    const loadFlows = fetch("/api/ids/flows?last=100")
      .then(r => r.json())
      .then(json => {
        const raw: object[] = Array.isArray(json) ? json : [];
        return raw.map((f: object) => ({ kind: "flow", ...(f as object) } as unknown as TrafficFlow));
      })
      .catch(() => [] as TrafficFlow[]);

    Promise.all([loadViolations, loadFlows]).then(([violations, flows]) => {
      // Merge and sort newest-first
      const merged: FeedEvent[] = [...violations, ...flows].sort(
        (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
      );
      setFeed(merged.slice(0, 300));
      setLoading(false);
    });
  }, []);

  // SSE real-time
  useEffect(() => {
    let es: EventSource;
    let reconnectTimer: ReturnType<typeof setTimeout>;

    const connect = () => {
      es = new EventSource("/api/ids/stream");
      es.onopen = () => { setConnStatus("live"); setLastUpdate(new Date()); };
      es.onerror = () => {
        setConnStatus("offline");
        es.close();
        reconnectTimer = setTimeout(connect, 3000);
      };
      es.onmessage = (evt) => {
        try {
          const data = JSON.parse(evt.data) as Record<string, unknown>;
          if (data?.type === "connected") { setConnStatus("live"); setLastUpdate(new Date()); return; }
          setConnStatus("live"); setLastUpdate(new Date());

          if (data?.type === "heartbeat") {
            const svc: ServiceStatus = {
              service:   data.service as string,
              zone:      data.zone as string,
              dest_ip:   data.dest_ip as string,
              status:    data.status === "up" ? "up" : data.status === "down" ? "down" : "unknown",
              timestamp: data.timestamp as string,
            };
            setServices(prev => new Map(prev).set(svc.service, svc));
            return;
          }

          if (data?.event_type === "flow") {
            const ev = { kind: "flow", ...data } as unknown as TrafficFlow;
            setFeed(prev => [ev, ...prev].slice(0, 600));
            return;
          }

          if (data?.alert) {
            const ev = { kind: "violation", ...data } as unknown as ViolationEvent;
            setFeed(prev => [ev, ...prev].slice(0, 600));
          }
        } catch {}
      };
    };

    connect();
    return () => { clearTimeout(reconnectTimer); es?.close(); };
  }, []);

  // Only auto-scroll when user is already near the top (< 120px scrolled)
  useEffect(() => {
    const el = scrollRef.current;
    if (el && el.scrollTop < 120) {
      topRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [feed.length]);

  // ── Derived ───────────────────────────────────────────────────────────────
  const violations = feed.filter(e => e.kind === "violation") as ViolationEvent[];
  const stats = {
    total: violations.length,
    p1: violations.filter(a => a.alert?.severity === 1).length,
    p2: violations.filter(a => a.alert?.severity === 2).length,
    p3: violations.filter(a => a.alert?.severity === 3).length,
    p4: violations.filter(a => a.alert?.severity === 4).length,
  };

  // Group by zone — node is "monitored" if any service in that zone has traffic
  const NODE_INFO: Record<string, { host: string; ip: string }> = {
    WEB: { host: "Alpine-Linux-1", ip: "10.1.100.10" },
    DB:  { host: "Alpine-Linux-2", ip: "10.1.200.10" },
    APP: { host: "Alpine-Linux-3", ip: "10.2.100.10" },
    MGT: { host: "Alpine-Linux-5", ip: "10.2.50.10"  },
  };
  const nodeStatus = (["WEB","DB","APP","MGT"] as const).map(zone => {
    const svcs = Array.from(services.values()).filter(s => s.zone === zone);
    const monitored = svcs.some(s => s.status === "up");
    return { zone, monitored, ...NODE_INFO[zone] };
  });
  const monitoredCount = nodeStatus.filter(n => n.monitored).length;

  const filtered = feed.filter(ev => {
    const zone = ev.kind === "violation" ? ipZone(ev.src_ip) : ipZone(ev.src_ip);
    if (filterZone !== "ALL" && zone !== filterZone) return false;
    if (ev.kind === "flow") return showFlows;
    if (filterPriority !== 0 && ev.alert?.severity !== filterPriority) return false;
    return true;
  });

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <main className="min-h-screen bg-tc-darker pt-20">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 py-8">

        {/* Header */}
        <div className="flex items-center gap-3 mb-6 flex-wrap">
          <h1 className="text-2xl font-bold text-white font-mono">Live Monitor</h1>
          {mounted && (
            <span className={`flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-mono border ${
              connStatus === "connecting" ? "bg-tc-card text-tc-text-dim border-tc-border"
              : connStatus === "live"    ? "bg-tc-green/10 text-tc-green border-tc-green/30"
                                         : "bg-red-900/20 text-red-400 border-red-700/30"
            }`}>
              <span className={`w-1.5 h-1.5 rounded-full ${
                connStatus === "live" ? "bg-tc-green animate-pulse" : "bg-tc-text-dim"
              }`} />
              {connStatus === "connecting" ? "CONNECTING" : connStatus === "live" ? "LIVE" : "OFFLINE"}
            </span>
          )}
          {mounted && lastUpdate && (
            <span className="text-xs font-mono text-tc-text-dim">
              {lastUpdate.toLocaleTimeString("vi-VN", { hour12: false })}
            </span>
          )}
          <span className="ml-auto text-xs text-tc-text-dim font-mono hidden sm:block">
            SSE real-time · alerts + flows · auto-reconnect
          </span>
        </div>

        {/* Service Health */}
        <div className="mb-5">
          <div className="flex items-baseline gap-3 mb-2">
            <span className="text-xs font-mono text-tc-text-dim uppercase tracking-wider">Nodes</span>
            <span className="text-xs font-mono text-tc-green font-bold">{monitoredCount}/4 monitored</span>
            <span className="text-xs text-tc-text-dim/60 font-mono normal-case">
              passive IDS · Suricata flow records · 3 min window
            </span>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            {nodeStatus.map(node => (
              <div key={node.zone}
                title={node.monitored
                  ? `Traffic observed from/to ${node.ip} in last 3 min (Suricata passive monitor)`
                  : `No recent traffic observed — node may be idle`}
                className={`rounded-lg border px-3 py-2.5 flex items-center gap-3 transition-all cursor-default ${
                  node.monitored
                    ? "border-tc-green/30 bg-tc-green/5"
                    : "border-tc-border bg-tc-card opacity-40"
                }`}>
                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${
                  node.monitored ? "bg-tc-green animate-pulse" : "bg-gray-600"
                }`} />
                <div className="min-w-0">
                  <div className="text-xs font-mono font-bold text-white">{node.zone}</div>
                  <div className="text-xs font-mono text-tc-text-dim">{node.host}</div>
                  <div className="text-xs font-mono text-tc-text-dim/60">{node.ip}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Violation Stats */}
        <div className="grid grid-cols-5 gap-2 mb-4">
          {[
            { label: "Violations", value: stats.total, color: "text-white" },
            { label: "P1 Critical", value: stats.p1,  color: "text-red-400" },
            { label: "P2 High",     value: stats.p2,  color: "text-orange-400" },
            { label: "P3 Info",     value: stats.p3,  color: "text-yellow-400" },
            { label: "P4 Audit",    value: stats.p4,  color: "text-tc-text-dim" },
          ].map(s => (
            <div key={s.label} className="rounded-lg border border-tc-border bg-tc-card px-3 py-2 text-center">
              <div className={`text-lg font-bold font-mono ${s.color}`}>{s.value}</div>
              <div className="text-xs text-tc-text-dim mt-0.5">{s.label}</div>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div className="flex flex-wrap gap-2 mb-4 items-center">
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-tc-text-dim font-mono">Zone:</span>
            {ZONES.map(z => (
              <button key={z} onClick={() => setFilterZone(z)}
                className={`px-2.5 py-1 rounded text-xs font-mono border transition-all ${
                  filterZone === z
                    ? "bg-tc-green text-black border-tc-green font-bold"
                    : "border-tc-border text-tc-text-dim hover:border-tc-green/30"
                }`}>{z}</button>
            ))}
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-tc-text-dim font-mono">P:</span>
            {([0,1,2,3,4] as Priority[]).map(p => (
              <button key={p} onClick={() => setFilterPriority(p)}
                className={`px-2.5 py-1 rounded text-xs font-mono border transition-all ${
                  filterPriority === p
                    ? "bg-tc-green text-black border-tc-green font-bold"
                    : "border-tc-border text-tc-text-dim hover:border-tc-green/30"
                }`}>{p === 0 ? "ALL" : `P${p}`}</button>
            ))}
          </div>
          <button onClick={() => setShowFlows(f => !f)}
            className={`px-2.5 py-1 rounded text-xs font-mono border transition-all ml-auto ${
              showFlows
                ? "bg-tc-green/10 text-tc-green border-tc-green/40"
                : "border-tc-border text-tc-text-dim"
            }`}>
            {showFlows ? "● Traffic ON" : "○ Traffic OFF"}
          </button>
        </div>

        {/* Unified Event Feed */}
        <div className="rounded-xl border border-tc-border bg-tc-card overflow-hidden">
          <div className="hidden sm:grid grid-cols-[120px_80px_1fr_1fr_90px_90px] gap-2 border-b border-tc-border px-4 py-2 text-xs font-mono text-tc-text-dim">
            <span>Time</span><span>Type</span><span>Src</span><span>Dst</span><span>Proto</span><span>Info</span>
          </div>
          <div ref={scrollRef} className="max-h-[65vh] overflow-y-auto">
            <div ref={topRef} />
            {loading ? (
              <div className="p-8 text-center font-mono text-tc-green text-sm animate-pulse">Loading...</div>
            ) : filtered.length === 0 ? (
              <div className="p-8 text-center font-mono text-tc-text-dim text-sm">
                {connStatus === "offline" ? "⚠ IDS Agent offline" : "No events."}
              </div>
            ) : (
              filtered.map((ev, i) => {
                if (ev.kind === "flow") {
                  const srcZone = ipZone(ev.src_ip);
                  const dstZone = ipZone(ev.dest_ip);
                  return (
                    <div key={`f-${i}`} className="border-b border-tc-border/20 border-l-2 border-l-tc-green/30 px-4 py-1.5 hover:bg-tc-green/3 transition-colors">
                      <div className="hidden sm:grid grid-cols-[120px_80px_1fr_1fr_90px_90px] gap-2 items-center">
                        <span className="text-xs font-mono text-tc-text-dim">{formatTime(ev.timestamp)}</span>
                        <span className="text-xs font-mono text-tc-green/70">FLOW</span>
                        <span className="text-xs font-mono text-tc-text-dim truncate">
                          <span className="text-tc-green/60">[{srcZone}]</span> {ev.src_ip}
                        </span>
                        <span className="text-xs font-mono text-tc-text-dim truncate">
                          <span className="text-tc-green/60">[{dstZone}]</span> {ev.dest_ip}:{ev.dest_port}
                        </span>
                        <span className="text-xs font-mono text-tc-text-dim">{ev.app_proto ?? ev.proto}</span>
                        <span className="text-xs font-mono text-tc-text-dim">{fmtBytes(ev.flow?.bytes_toserver)}</span>
                      </div>
                      <div className="sm:hidden text-xs font-mono text-tc-text-dim">
                        <span className="text-tc-green/70">FLOW </span>
                        {ev.src_ip} → {ev.dest_ip}:{ev.dest_port} [{dstZone}]
                      </div>
                    </div>
                  );
                }

                // violation
                const sev = ev.alert?.severity;
                return (
                  <div key={`v-${i}`} className={`border-b border-tc-border/40 border-l-2 px-4 py-2.5 hover:bg-white/2 transition-colors ${
                    PRIORITY_ROW[sev] ?? PRIORITY_ROW[4]
                  }`}>
                    <div className="hidden sm:grid grid-cols-[120px_80px_1fr_1fr_90px_90px] gap-2 items-center">
                      <span className="text-xs font-mono text-tc-text-dim">{formatTime(ev.timestamp)}</span>
                      <span className={`px-1.5 py-0.5 rounded border text-xs font-mono font-bold w-fit ${PRIORITY_BADGE[sev] ?? PRIORITY_BADGE[4]}`}>
                        {PRIORITY_LABEL[sev] ?? `P${sev}`}
                      </span>
                      <span className="text-xs font-mono text-tc-text-dim truncate">
                        <span className="text-red-400">[{ipZone(ev.src_ip)}]</span> {ev.src_ip}
                      </span>
                      <span className="text-xs font-mono text-tc-text-dim truncate">
                        {ev.dest_ip}
                      </span>
                      <span className="text-xs font-mono text-tc-text-dim">{ev.proto}</span>
                      <span className="text-xs text-tc-text truncate" title={ev.alert?.signature}>
                        {ev.alert?.signature?.replace(/^\[ZT-[^\]]+\]\s*/,"")}
                      </span>
                    </div>
                    <div className="sm:hidden">
                      <div className="flex justify-between mb-0.5">
                        <span className="text-xs text-tc-text-dim font-mono">{formatTs(ev.timestamp)}</span>
                        <span className={`px-1.5 py-0.5 rounded border text-xs font-mono font-bold ${PRIORITY_BADGE[sev] ?? PRIORITY_BADGE[4]}`}>
                          {PRIORITY_LABEL[sev]}
                        </span>
                      </div>
                      <div className="text-xs text-tc-text">{ev.alert?.signature}</div>
                      <div className="text-xs font-mono text-tc-text-dim">{ev.src_ip} → {ev.dest_ip}</div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        <p className="mt-2 text-xs text-tc-text-dim font-mono text-right">
          {filtered.filter(e => e.kind === "flow").length} flows · {filtered.filter(e => e.kind === "violation").length} violations
        </p>
      </div>
    </main>
  );
}
