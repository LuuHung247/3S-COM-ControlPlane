"use client";

import { useEffect, useRef, useState } from "react";
import { AgentNotificationFeed } from "@/components/AgentNotificationFeed";

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

// ── Server-side events buffer ─────────────────────────────────────────────────
// Events (alerts + flows) are persisted in Redis DB 1 (7-day retention) by
// intelligence-layer. Frontend hydrates from /api/intel/events on mount, so F5
// no longer flashes blank. SSE stream still appends real-time on top.
const FEED_DISPLAY_MAX = 600;

function eventKey(ev: FeedEvent): string {
  if (ev.kind === "violation") {
    return `v|${ev.timestamp}|${ev.alert?.signature_id ?? ""}|${ev.src_ip}|${ev.dest_ip}`;
  }
  return `f|${ev.timestamp}|${ev.src_ip}|${ev.src_port}|${ev.dest_ip}|${ev.dest_port}`;
}

function dedupMerge(...lists: FeedEvent[][]): FeedEvent[] {
  const seen = new Map<string, FeedEvent>();
  for (const list of lists) {
    for (const ev of list) {
      const k = eventKey(ev);
      if (!seen.has(k)) seen.set(k, ev);
    }
  }
  return Array.from(seen.values()).sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );
}

// Coerce backend /events response (raw Suricata-shape items with __kind hint)
// into our FeedEvent union. Backend stores both alerts and flows.
function coerceServerEvent(raw: Record<string, unknown>): FeedEvent | null {
  const kind = raw.__kind as string | undefined;
  if (kind === "violation" || raw.alert) {
    return { kind: "violation", ...raw } as unknown as ViolationEvent;
  }
  if (kind === "flow" || raw.event_type === "flow") {
    return { kind: "flow", ...raw } as unknown as TrafficFlow;
  }
  return null;
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
  const [autoFollow, setAutoFollow] = useState(true);     // auto-scroll to top on new events
  const [pendingNew, setPendingNew] = useState(0);        // count of events arrived while paused
  const [agentTrigger, setAgentTrigger] = useState<boolean | null>(null);   // null = unknown

  // Fetch agent trigger state on mount, refresh every 10s
  useEffect(() => {
    let cancelled = false;
    const refresh = async () => {
      try {
        const res = await fetch("/api/intel/admin/trigger", { cache: "no-store" });
        const data = await res.json();
        if (!cancelled && typeof data.enabled === "boolean") setAgentTrigger(data.enabled);
      } catch {
        if (!cancelled) setAgentTrigger(null);
      }
    };
    refresh();
    const id = window.setInterval(refresh, 10_000);
    return () => { cancelled = true; window.clearInterval(id); };
  }, []);

  const toggleAgent = async () => {
    if (agentTrigger === null) return;
    const next = !agentTrigger;
    setAgentTrigger(next);                       // optimistic
    try {
      const res = await fetch("/api/intel/admin/trigger", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: next }),
      });
      const data = await res.json();
      if (typeof data.enabled === "boolean") setAgentTrigger(data.enabled);
    } catch {
      setAgentTrigger(!next);                    // rollback
    }
  };
  const topRef      = useRef<HTMLDivElement>(null);
  const scrollRef   = useRef<HTMLDivElement>(null);

  // Flow batch window status — countdown + buffered flow count
  const [batchStatus, setBatchStatus] = useState<{
    enabled: boolean;
    windowSeconds: number;
    bufferSize: number;
    windowStart: string;
  } | null>(null);

  useEffect(() => {
    let cancelled = false;
    const refresh = async () => {
      try {
        const res = await fetch("/api/intel/admin/flow-batch", { cache: "no-store" });
        const d = await res.json();
        if (!cancelled && d.enabled) {
          setBatchStatus({
            enabled: true,
            windowSeconds: d.window_seconds ?? 120,
            bufferSize: d.buffer_size ?? 0,
            windowStart: d.window_start ?? "",
          });
        } else if (!cancelled) {
          setBatchStatus(null);
        }
      } catch {
        if (!cancelled) setBatchStatus(null);
      }
    };
    refresh();
    const id = window.setInterval(refresh, 3000);
    return () => { cancelled = true; window.clearInterval(id); };
  }, []);

  // Compute seconds remaining in current window
  const batchCountdown = (() => {
    if (!batchStatus || !batchStatus.windowStart) return null;
    const start = new Date(batchStatus.windowStart).getTime();
    const end = start + batchStatus.windowSeconds * 1000;
    const remaining = Math.max(0, Math.round((end - Date.now()) / 1000));
    return remaining;
  })();

  useEffect(() => { setMounted(true); }, []);

  // Load history on mount from server-side Redis buffer (7-day window).
  // Falls back to Suricata transient API only if intel layer unavailable.
  useEffect(() => {
    fetch("/api/intel/events?limit=600")
      .then(r => r.ok ? r.json() : [])
      .then((raw: unknown) => {
        if (!Array.isArray(raw) || raw.length === 0) {
          // Fallback: Suricata transient API (3-min window)
          return Promise.all([
            fetch("/api/ids/alerts?last=50").then(r => r.json()).catch(() => []),
            fetch("/api/ids/flows?last=100").then(r => r.json()).catch(() => []),
          ]).then(([alertsJson, flowsJson]) => {
            const alerts: FeedEvent[] = (Array.isArray(alertsJson) ? alertsJson : (alertsJson.alerts ?? []))
              .map((a: object) => ({ kind: "violation", ...(a as object) } as unknown as ViolationEvent));
            const flows: FeedEvent[] = (Array.isArray(flowsJson) ? flowsJson : [])
              .map((f: object) => ({ kind: "flow", ...(f as object) } as unknown as TrafficFlow));
            return dedupMerge(alerts, flows);
          });
        }
        const events: FeedEvent[] = [];
        for (const r of raw) {
          const ev = coerceServerEvent(r as Record<string, unknown>);
          if (ev) events.push(ev);
        }
        return dedupMerge(events);
      })
      .then((merged) => {
        setFeed(merged.slice(0, FEED_DISPLAY_MAX));
        setLoading(false);
      })
      .catch(() => setLoading(false));
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

  // Flow poller: Suricata /stream SSE only broadcasts alerts (by design — flow
  // rate would flood subscribers). Flows reach Redis DB 1 via intel-layer's
  // own poll loop; here we pull newly-stored flows every 5s into the feed so
  // Monitor stays current without an F5. De-dup by flow_id+timestamp.
  // De-dup against current feed inside setFeed callback so we never double-add
  // flows that hydration already loaded.
  useEffect(() => {
    let cancelled = false;
    const flowKey = (f: Record<string, unknown>) =>
      `${f.flow_id ?? ""}|${f.timestamp ?? ""}|${f.src_ip ?? ""}|${f.src_port ?? ""}`;

    const tick = async () => {
      if (cancelled) return;
      try {
        const r = await fetch("/api/intel/events?kind=flow&limit=50");
        if (!r.ok) return;
        const arr = await r.json();
        if (!Array.isArray(arr) || arr.length === 0) return;

        setFeed(prev => {
          const seen = new Set(
            prev.filter(e => e.kind === "flow")
                .map(e => flowKey(e as unknown as Record<string, unknown>))
          );
          const fresh: TrafficFlow[] = [];
          for (const raw of arr) {
            const r0 = raw as Record<string, unknown>;
            const k = flowKey(r0);
            if (seen.has(k)) continue;
            seen.add(k);
            fresh.push({ kind: "flow", ...r0 } as unknown as TrafficFlow);
          }
          if (fresh.length === 0) return prev;
          return [...fresh, ...prev].slice(0, FEED_DISPLAY_MAX);
        });
      } catch {}
    };

    const interval = setInterval(tick, 5000);
    return () => { cancelled = true; clearInterval(interval); };
  }, []);

  // Auto-follow: when new events arrive, scroll to top (where newest items render).
  // If user has scrolled away (>250px), pause follow and accumulate "N new" badge.
  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    if (autoFollow) {
      // Instant scroll to keep feed pinned to newest item
      el.scrollTop = 0;
      setPendingNew(0);
    } else {
      setPendingNew((c) => c + 1);
    }
  }, [feed.length, autoFollow]);

  // Detect manual scroll: if user scrolled away from top, pause auto-follow.
  // If user scrolled back near top, resume.
  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const onScroll = () => {
      const atTop = el.scrollTop < 80;
      if (atTop && !autoFollow) {
        setAutoFollow(true);
      } else if (!atTop && autoFollow && el.scrollTop > 250) {
        setAutoFollow(false);
      }
    };
    el.addEventListener("scroll", onScroll, { passive: true });
    return () => el.removeEventListener("scroll", onScroll);
  }, [autoFollow]);

  // Resume follow + jump to top
  const resumeFollow = () => {
    setAutoFollow(true);
    setPendingNew(0);
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
  };

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
    const zone = ipZone(ev.src_ip);
    if (filterZone !== "ALL" && zone !== filterZone) return false;
    if (ev.kind === "flow") {
      // Priority filters (P1/P2/P3/P4) are alert-severity filters — when one is
      // active, the user is inspecting violations, so suppress flow noise.
      if (filterPriority !== 0) return false;
      return showFlows;
    }
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
          {mounted && (
            <button
              onClick={toggleAgent}
              disabled={agentTrigger === null}
              title={
                agentTrigger === null
                  ? "Agent state unknown (intel offline?)"
                  : agentTrigger
                    ? "Click to PAUSE agent (flows still ingest, no decisions)"
                    : "Click to RESUME agent (decisions will fire on next event)"
              }
              className={`ml-auto flex items-center gap-2 rounded-full px-3 py-1 text-xs font-mono border transition-all ${
                agentTrigger === null
                  ? "bg-tc-card text-tc-text-dim border-tc-border cursor-not-allowed"
                  : agentTrigger
                    ? "bg-tc-green/10 text-tc-green border-tc-green/30 hover:bg-tc-green/20"
                    : "bg-amber-500/10 text-amber-400 border-amber-500/40 hover:bg-amber-500/20"
              }`}>
              <span className={`w-1.5 h-1.5 rounded-full ${
                agentTrigger === null ? "bg-tc-text-dim"
                : agentTrigger ? "bg-tc-green animate-pulse"
                : "bg-amber-400"
              }`} />
              Agent: {agentTrigger === null ? "?" : agentTrigger ? "ON" : "OFF"}
            </button>
          )}
          <span className="text-xs text-tc-text-dim font-mono hidden sm:block">
            Pure flow-log mode · NetVigil-aligned · 2-min window
          </span>
        </div>

        {/* Flow Batch Status — replaces SID-based alert panel for pure-log mode */}
        {mounted && batchStatus && (
          <div className="mb-5 rounded-lg border border-tc-border bg-tc-card p-3">
            <div className="flex items-center justify-between flex-wrap gap-3">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-tc-text-dim uppercase tracking-wider">
                  Flow batch window
                </span>
                <span className="text-xs font-mono text-tc-green font-bold">
                  {batchStatus.windowSeconds}s
                </span>
              </div>
              <div className="flex items-center gap-4">
                <div className="text-xs font-mono text-tc-text-dim">
                  Buffered:{" "}
                  <span className="text-white font-bold">{batchStatus.bufferSize}</span>{" "}
                  <span className="text-tc-text-dim/60">flows</span>
                </div>
                <div className="text-xs font-mono text-tc-text-dim">
                  Next batch in:{" "}
                  <span className={`font-bold ${
                    batchCountdown !== null && batchCountdown <= 10
                      ? "text-amber-400 animate-pulse"
                      : "text-white"
                  }`}>
                    {batchCountdown !== null ? `${batchCountdown}s` : "—"}
                  </span>
                </div>
                {agentTrigger === false && (
                  <span className="text-xs font-mono text-amber-400">
                    Agent paused — flows ingest, decisions skipped
                  </span>
                )}
              </div>
            </div>
            <div className="mt-2 h-1 rounded-full bg-tc-darker overflow-hidden">
              <div
                className="h-full bg-tc-green transition-all"
                style={{
                  width: batchCountdown !== null
                    ? `${100 - (batchCountdown / batchStatus.windowSeconds) * 100}%`
                    : "0%",
                }}
              />
            </div>
          </div>
        )}

        {/* Service Health */}
        <div className="mb-5">
          <div className="flex items-baseline gap-3 mb-2">
            <span className="text-xs font-mono text-tc-text-dim uppercase tracking-wider">Nodes</span>
            <span className="text-xs font-mono text-tc-green font-bold">{monitoredCount}/4 monitored</span>
            <span className="text-xs text-tc-text-dim/60 font-mono normal-case">
              passive IDS · Suricata eve.json flow logs · 2 min batch window
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
          <button onClick={() => setAutoFollow(f => !f)}
            title={autoFollow
              ? "Auto-scroll to newest event (click to pause)"
              : "Paused — click to resume auto-scroll"}
            className={`px-2.5 py-1 rounded text-xs font-mono border transition-all ${
              autoFollow
                ? "bg-tc-green/10 text-tc-green border-tc-green/40"
                : "border-orange-600/40 text-orange-400 bg-orange-900/15"
            }`}>
            {autoFollow ? "⇣ Follow ON" : "⏸ Follow OFF"}
          </button>
        </div>

        {/* Unified Event Feed */}
        <div className="rounded-xl border border-tc-border bg-tc-card overflow-hidden relative">
          <div className="hidden sm:grid grid-cols-[120px_80px_1fr_1fr_90px_90px] gap-2 border-b border-tc-border px-4 py-2 text-xs font-mono text-tc-text-dim">
            <span>Time</span><span>Type</span><span>Src</span><span>Dst</span><span>Proto</span><span>Info</span>
          </div>

          {/* Floating "N new events" pill — visible while user has paused follow */}
          {!autoFollow && pendingNew > 0 && (
            <button
              onClick={resumeFollow}
              className="absolute top-12 left-1/2 -translate-x-1/2 z-10 px-3 py-1.5 rounded-full bg-tc-green text-black border border-tc-green text-xs font-mono font-bold shadow-lg hover:scale-105 transition-transform animate-pulse"
            >
              ↑ {pendingNew} new event{pendingNew > 1 ? "s" : ""} — click to resume
            </button>
          )}

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

        <div className="mt-2 flex items-center justify-between text-xs text-tc-text-dim font-mono">
          <span className="text-tc-text-dim/70">
            server buffer · Redis DB1 · 7-day retention · auto-prune
          </span>
          <span>
            {filtered.filter(e => e.kind === "flow").length} flows · {filtered.filter(e => e.kind === "violation").length} violations · loaded {feed.length}/{FEED_DISPLAY_MAX}
          </span>
        </div>
      </div>

      <AgentNotificationFeed />
    </main>
  );
}
