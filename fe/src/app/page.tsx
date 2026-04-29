"use client";

import { useEffect, useState } from "react";
import ScrollReveal from "@/components/ScrollReveal";

interface HealthData {
  status: string;
  suricata: string;
  alerts_total: number;
  uptime_seconds: number;
}

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

function priorityBadge(p: number) {
  const map: Record<number, string> = {
    1: "bg-red-900/60 text-red-400 border-red-700/50",
    2: "bg-orange-900/60 text-orange-400 border-orange-700/50",
    3: "bg-yellow-900/60 text-yellow-400 border-yellow-700/50",
    4: "bg-tc-card text-tc-text-dim border-tc-border",
  };
  const label: Record<number, string> = { 1: "P1 CRITICAL", 2: "P2 HIGH", 3: "P3 INFO", 4: "P4 AUDIT" };
  return (
    <span className={`px-2 py-0.5 rounded border text-xs font-mono font-bold ${map[p] ?? map[4]}`}>
      {label[p] ?? `P${p}`}
    </span>
  );
}

function formatTs(ts: string) {
  try {
    return new Date(ts).toLocaleTimeString("vi-VN", { hour12: false });
  } catch {
    return ts;
  }
}

function ipZone(ip: string) {
  if (ip.startsWith("10.1.100.")) return "WEB";
  if (ip.startsWith("10.1.200.")) return "DB";
  if (ip.startsWith("10.2.100.")) return "APP";
  if (ip.startsWith("10.2.50.")) return "MGT";
  return "—";
}

export default function HomePage() {
  const [health, setHealth] = useState<HealthData | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [totalAlerts, setTotalAlerts] = useState(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      fetch("/api/ids/health").then((r) => r.json()).catch(() => null),
      fetch("/api/ids/alerts?last=5").then((r) => r.json()).catch(() => []),
      fetch("/api/ids/alerts").then((r) => r.json()).catch(() => null),
    ]).then(([h, a, all]) => {
      setHealth(h);
      const arr = Array.isArray(a) ? a : (a?.alerts ?? []);
      setAlerts(arr.slice(0, 5));
      setTotalAlerts(all?.count ?? arr.length);
      setLoading(false);
    });
  }, []);

  const violations = alerts.filter((a) => a.alert?.severity <= 2).length;
  const totalToday = totalAlerts;

  const statCards = [
    {
      label: "IDS Status",
      value: loading ? "..." : health?.status === "ok" ? "ONLINE" : "OFFLINE",
      sub: loading ? "" : health?.suricata ?? "",
      color: health?.status === "ok" ? "text-tc-green" : "text-red-400",
      icon: "🛡️",
    },
    {
      label: "Total Alerts",
      value: loading ? "..." : String(totalToday),
      sub: "all time",
      color: "text-tc-green",
      icon: "🔔",
    },
    {
      label: "Policy Violations",
      value: loading ? "..." : String(violations),
      sub: "last 5 alerts (P1+P2)",
      color: violations > 0 ? "text-red-400" : "text-tc-green",
      icon: "🚨",
    },
    {
      label: "Zones Monitored",
      value: "4",
      sub: "WEB · DB · APP · MGT",
      color: "text-tc-green",
      icon: "🗺️",
    },
  ];

  return (
    <main className="min-h-screen bg-tc-darker pt-20">
      {/* Hero */}
      <section className="relative overflow-hidden py-16 sm:py-24">
        <div className="matrix-bg absolute inset-0 pointer-events-none" />
        <div className="mx-auto max-w-6xl px-6 relative">
          <ScrollReveal>
            <div className="mb-3 inline-flex items-center rounded-full border border-tc-green/20 bg-tc-green/5 px-4 py-1.5 text-xs font-mono text-tc-green">
              NIST 800-207 · Zero Trust Architecture
            </div>
          </ScrollReveal>
          <ScrollReveal delay={100}>
            <h1 className="mt-4 text-4xl sm:text-6xl font-bold text-white glow-green-strong leading-tight">
              3S-NOS
            </h1>
            <h2 className="text-2xl sm:text-3xl font-bold text-tc-green font-mono mt-1">
              Spine-Leaf DC Fabric
            </h2>
          </ScrollReveal>
          <ScrollReveal delay={200}>
            <p className="mt-4 max-w-2xl text-tc-text-dim text-base sm:text-lg">
              GNS3 datacenter network với SONiC Spine-Leaf topology, microsegmentation iptables,
              và Suricata IDS real-time monitoring theo dõi vi phạm chính sách Zero Trust.
            </p>
          </ScrollReveal>
          <ScrollReveal delay={300}>
            <div className="mt-8 flex flex-wrap gap-4">
              <a
                href="/monitor"
                className="rounded-xl bg-tc-green px-6 py-3 font-bold text-black transition-all hover:bg-tc-green-dim pulse-glow"
              >
                Live Monitor →
              </a>
              <a
                href="/topology"
                className="rounded-xl border border-tc-green/30 px-6 py-3 font-medium text-tc-green transition-all hover:bg-tc-green/10"
              >
                View Topology
              </a>
            </div>
          </ScrollReveal>
        </div>
      </section>

      {/* Stats */}
      <section className="py-12">
        <div className="mx-auto max-w-6xl px-6">
          <ScrollReveal>
            <p className="mb-6 font-mono text-xs text-tc-green tracking-wider uppercase">
              System Status
            </p>
          </ScrollReveal>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {statCards.map((card, i) => (
              <ScrollReveal key={card.label} delay={i * 80}>
                <div className="rounded-xl border border-tc-border bg-tc-card p-5 transition-all hover:border-tc-green/30 glow-box-hover">
                  <div className="text-2xl mb-2">{card.icon}</div>
                  <div className={`text-2xl font-bold font-mono ${card.color}`}>
                    {card.value}
                  </div>
                  <div className="mt-1 text-xs text-tc-text-dim">{card.label}</div>
                  {card.sub && (
                    <div className="mt-0.5 text-xs text-tc-text-dim/60 font-mono">{card.sub}</div>
                  )}
                </div>
              </ScrollReveal>
            ))}
          </div>
        </div>
      </section>

      {/* Recent Alerts */}
      <section className="py-12">
        <div className="mx-auto max-w-6xl px-6">
          <ScrollReveal>
            <div className="flex items-center justify-between mb-6">
              <p className="font-mono text-xs text-tc-green tracking-wider uppercase">
                Recent Alerts
              </p>
              <a href="/monitor" className="text-xs text-tc-text-dim hover:text-tc-green transition-colors font-mono">
                View all →
              </a>
            </div>
          </ScrollReveal>
          <ScrollReveal delay={100}>
            <div className="rounded-xl border border-tc-border bg-tc-card overflow-hidden">
              {loading ? (
                <div className="p-8 text-center font-mono text-tc-green text-sm animate-pulse">
                  Loading alerts...
                </div>
              ) : alerts.length === 0 ? (
                <div className="p-8 text-center font-mono text-tc-text-dim text-sm">
                  No alerts yet. Generate traffic to see detections.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-tc-border text-xs font-mono text-tc-text-dim">
                        <th className="px-4 py-3 text-left">Time</th>
                        <th className="px-4 py-3 text-left">Rule</th>
                        <th className="px-4 py-3 text-left">Src → Dst</th>
                        <th className="px-4 py-3 text-left">Zone</th>
                        <th className="px-4 py-3 text-left">Priority</th>
                      </tr>
                    </thead>
                    <tbody>
                      {alerts.map((a, i) => (
                        <tr
                          key={i}
                          className="border-b border-tc-border/50 hover:bg-tc-green/5 transition-colors"
                        >
                          <td className="px-4 py-3 font-mono text-xs text-tc-text-dim whitespace-nowrap">
                            {formatTs(a.timestamp)}
                          </td>
                          <td className="px-4 py-3 text-tc-text text-xs max-w-xs truncate">
                            {a.alert?.signature}
                          </td>
                          <td className="px-4 py-3 font-mono text-xs text-tc-text-dim whitespace-nowrap">
                            {a.src_ip} → {a.dest_ip}
                          </td>
                          <td className="px-4 py-3 font-mono text-xs text-tc-green">
                            {ipZone(a.src_ip)}
                          </td>
                          <td className="px-4 py-3">
                            {priorityBadge(a.alert?.severity)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </ScrollReveal>
        </div>
      </section>

      {/* Architecture Summary */}
      <section className="py-12">
        <div className="mx-auto max-w-6xl px-6">
          <ScrollReveal>
            <p className="mb-6 font-mono text-xs text-tc-green tracking-wider uppercase">
              Architecture
            </p>
          </ScrollReveal>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[
              {
                title: "Spine-Leaf Fabric",
                desc: "SONiC-VS Spine + 2 LEAF switches. BGP ECMP routing. 4 Alpine Linux hosts in 4 microsegment zones.",
                icon: "🌐",
              },
              {
                title: "Zero Trust Policy",
                desc: "12/12 iptables rules verified. WEB→DB blocked. DB outbound blocked. Cross-zone lateral movement prevented.",
                icon: "🔒",
              },
              {
                title: "IDS Monitoring",
                desc: "Suricata 8.0 với tc mirred ingress mirroring từ LEAF-1 & LEAF-2. 8 detection rules, REST API port 8765.",
                icon: "👁️",
              },
            ].map((item, i) => (
              <ScrollReveal key={item.title} delay={i * 100}>
                <div className="rounded-xl border border-tc-border bg-tc-card p-6 transition-all hover:border-tc-green/30 glow-box-hover h-full">
                  <div className="text-3xl mb-3">{item.icon}</div>
                  <h3 className="font-bold text-white mb-2">{item.title}</h3>
                  <p className="text-sm text-tc-text-dim leading-relaxed">{item.desc}</p>
                </div>
              </ScrollReveal>
            ))}
          </div>
        </div>
      </section>
    </main>
  );
}
