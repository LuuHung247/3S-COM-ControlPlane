"use client";

import { useEffect, useRef, useState } from "react";

type Severity = "info" | "warn" | "alert" | "critical";

interface NotificationRecord {
  id: string;
  timestamp: string;
  alert_sid: number;
  attacker_ip: string;
  action: string | null;
  block_dst: string | null;    // intent.dst_ip — used for flow-level dedup
  decision: string;            // enforced | dry_run | rejected
  rejection_reason: string;
  notification: {
    title: string;
    body: string;
    severity: Severity;
  } | null;
}

// Multiple Suricata SIDs may fire on the same flow (e.g. 9000001 + 9000051 both
// detect WEB→DB), producing several decisions a few seconds apart. Collapse them
// into the first one shown so the SOC feed reads as one event per attack.
const DEDUP_WINDOW_MS = 60_000;

function dedupByFlow(shown: NotificationRecord[]): NotificationRecord[] {
  // API returns newest-first; walk oldest→newest so the first chronological
  // occurrence wins (stable across polls — once shown, doesn't get replaced).
  const firstTs = new Map<string, number>();
  const oldestFirst = [...shown].reverse();
  const kept: NotificationRecord[] = [];
  for (const d of oldestFirst) {
    const ts = Date.parse(d.timestamp);
    const key = `${d.attacker_ip}|${d.action ?? "none"}|${d.block_dst ?? ""}`;
    const t0 = firstTs.get(key);
    if (t0 !== undefined && ts - t0 < DEDUP_WINDOW_MS) continue;
    firstTs.set(key, ts);
    kept.push(d);
  }
  return kept.reverse();
}

const SEVERITY_STYLES: Record<Severity, { row: string; badge: string; label: string }> = {
  info: {
    row: "border-l-tc-border bg-tc-card",
    badge: "bg-tc-card text-tc-text-dim border-tc-border",
    label: "INFO",
  },
  warn: {
    row: "border-l-yellow-500 bg-yellow-950/10",
    badge: "bg-yellow-900/60 text-yellow-400 border-yellow-700/50",
    label: "WARN",
  },
  alert: {
    row: "border-l-orange-500 bg-orange-950/20",
    badge: "bg-orange-900/60 text-orange-400 border-orange-700/50",
    label: "ALERT",
  },
  critical: {
    row: "border-l-red-500 bg-red-950/20",
    badge: "bg-red-900/60 text-red-400 border-red-700/50",
    label: "CRITICAL",
  },
};

const POLL_INTERVAL_MS = 3000;
const TOAST_DURATION_MS = 8000;
const FEED_MAX = 50;

function fmtTime(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString("en-GB", { hour12: false });
  } catch {
    return iso;
  }
}

export function AgentNotificationFeed() {
  const [items, setItems] = useState<NotificationRecord[]>([]);
  const [toast, setToast] = useState<NotificationRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const seenIds = useRef<Set<string>>(new Set());
  const firstLoad = useRef(true);
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    let cancelled = false;

    const tick = async () => {
      try {
        const r = await fetch("/api/intel/decisions");
        if (!r.ok) return;
        const data = (await r.json()) as NotificationRecord[];
        if (cancelled || !Array.isArray(data)) return;

        // SOC feed shows only enforced DROPs — the actions the agent actually
        // took on the data plane. log_only observations, held/rejected
        // decisions, and other non-enforcement events stay out of the feed to
        // keep it focused on real interventions.
        const shown = dedupByFlow(
          data.filter(
            (d) =>
              d.notification?.title &&
              d.decision === "enforced" &&
              d.action === "DROP",
          ),
        );
        if (firstLoad.current) {
          firstLoad.current = false;
          shown.forEach((d) => seenIds.current.add(d.id));
          setItems(shown.slice(0, FEED_MAX));
          setLoading(false);
          return;
        }

        const fresh: NotificationRecord[] = [];
        for (const d of shown) {
          if (!seenIds.current.has(d.id)) {
            seenIds.current.add(d.id);
            fresh.push(d);
          }
        }
        if (fresh.length > 0) {
          setItems((prev) => [...fresh, ...prev].slice(0, FEED_MAX));
          // Show toast for the most recent new decision
          const latest = fresh[0];
          setToast(latest);
          if (toastTimer.current) clearTimeout(toastTimer.current);
          toastTimer.current = setTimeout(() => setToast(null), TOAST_DURATION_MS);
        }
      } catch {
        // swallow — next tick retries
      }
    };

    tick();
    const interval = setInterval(tick, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(interval);
      if (toastTimer.current) clearTimeout(toastTimer.current);
    };
  }, []);

  return (
    <>
      {/* Toast — transient pop-up for newest decision */}
      {toast?.notification && (
        <div className="fixed bottom-6 right-6 z-50 max-w-md animate-slide-in">
          <div className="rounded-xl border-l-4 border-l-red-500/70 border border-tc-border bg-tc-card p-4 shadow-2xl backdrop-blur-md">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-mono text-tc-text-dim">
                SID #{toast.alert_sid} · {fmtTime(toast.timestamp)}
              </span>
              <button
                type="button"
                className="ml-auto text-tc-text-dim hover:text-tc-green text-xs"
                onClick={() => setToast(null)}
                aria-label="Dismiss"
              >
                ✕
              </button>
            </div>
            <p className="text-sm font-semibold text-white mb-1">
              {toast.notification.title}
            </p>
            <p className="text-xs text-tc-text-dim leading-relaxed">
              {toast.notification.body}
            </p>
          </div>
        </div>
      )}

      {/* Feed panel — persistent activity log */}
      <section className="mt-8">
        <div className="mx-auto max-w-6xl px-6">
          <div className="flex items-center justify-between mb-4">
            <p className="font-mono text-xs text-tc-green tracking-wider uppercase">
              Agent Notifications
            </p>
            <span className="text-xs font-mono text-tc-text-dim">
              {items.length} message{items.length !== 1 ? "s" : ""}
            </span>
          </div>
          <div className="rounded-xl border border-tc-border bg-tc-card overflow-hidden max-h-[60vh] overflow-y-auto">
            {loading && items.length === 0 ? (
              <div className="p-8 text-center font-mono text-tc-text-dim text-sm">
                Loading notifications…
              </div>
            ) : items.length === 0 ? (
              <div className="p-8 text-center font-mono text-tc-text-dim text-sm">
                No agent notifications yet.
              </div>
            ) : (
              <ul className="divide-y divide-tc-border/40">
                {items.map((d) => {
                  const isRejected = d.decision === "rejected";
                  // Feed shows only enforced DROPs in current filter — all rows
                  // are uniform; severity badge dropped to keep the demo clean.
                  return (
                    <li
                      key={d.id}
                      className="flex flex-col gap-1 border-l-4 border-l-red-500/70 bg-tc-card px-4 py-3"
                    >
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-mono text-tc-text-dim">
                          {fmtTime(d.timestamp)}
                        </span>
                        <span className="text-xs font-mono text-tc-text-dim/70">
                          SID #{d.alert_sid}
                        </span>
                        <span className="text-xs font-mono text-tc-text-dim/70">
                          {d.attacker_ip}
                        </span>
                        {d.action && (
                          <span className="rounded border border-tc-border px-2 py-0.5 text-[10px] font-mono uppercase text-tc-text-dim">
                            {d.action}
                          </span>
                        )}
                      </div>
                      {isRejected ? (
                        <>
                          <p className="text-sm font-semibold text-white">
                            {d.notification?.title || "Safety gate blocked decision"}
                          </p>
                          <p className="text-xs text-violet-300/90 leading-relaxed font-mono break-words">
                            {d.rejection_reason}
                          </p>
                          {d.notification?.body && (
                            <p className="text-xs text-tc-text-dim leading-relaxed">
                              Agent intent: {d.notification.body}
                            </p>
                          )}
                        </>
                      ) : (
                        <>
                          <p className="text-sm font-semibold text-white">{d.notification?.title}</p>
                          <p className="text-xs text-tc-text-dim leading-relaxed">{d.notification?.body}</p>
                        </>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </div>
      </section>
    </>
  );
}
