"use client";

import { useEffect, useRef, useState } from "react";

type Severity = "info" | "warn" | "alert" | "critical";

interface NotificationRecord {
  id: string;
  timestamp: string;
  alert_sid: number;
  attacker_ip: string;
  action: string | null;
  decision: string;            // enforced | dry_run | rejected
  rejection_reason: string;
  notification: {
    title: string;
    body: string;
    severity: Severity;
  } | null;
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

        // Show all decisions that have either a notification OR a rejection.
        // This lets the SOC see L3/L4/L5 safety-gate rejections too, not just
        // successful enforcements.
        const shown = data.filter(
          (d) => d.notification?.title || d.decision === "rejected",
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
          <div
            className={`rounded-xl border-l-4 border border-tc-border p-4 shadow-2xl backdrop-blur-md ${SEVERITY_STYLES[toast.notification.severity].row}`}
          >
            <div className="flex items-center gap-2 mb-1">
              <span
                className={`rounded border px-2 py-0.5 text-[10px] font-mono uppercase ${SEVERITY_STYLES[toast.notification.severity].badge}`}
              >
                {SEVERITY_STYLES[toast.notification.severity].label}
              </span>
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
                  // Rejected rows: blue/violet styling regardless of notification severity.
                  // They represent safety-gate blocks (L3/L4/L5), not enforcement actions.
                  const sty = isRejected
                    ? {
                        row: "border-l-violet-500 bg-violet-950/15",
                        badge: "bg-violet-900/60 text-violet-300 border-violet-700/50",
                        label: "REJECTED",
                      }
                    : SEVERITY_STYLES[d.notification?.severity ?? "info"];
                  return (
                    <li
                      key={d.id}
                      className={`flex flex-col gap-1 border-l-4 px-4 py-3 ${sty.row}`}
                    >
                      <div className="flex items-center gap-2 flex-wrap">
                        <span
                          className={`rounded border px-2 py-0.5 text-[10px] font-mono uppercase ${sty.badge}`}
                        >
                          {sty.label}
                        </span>
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
