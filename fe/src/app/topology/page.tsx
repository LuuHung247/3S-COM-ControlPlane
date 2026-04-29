"use client";

import ScrollReveal from "@/components/ScrollReveal";

const zones = [
  {
    name: "WEB",
    subnet: "10.1.100.0/24",
    host: "Alpine-1",
    ip: "10.1.100.2",
    leaf: "LEAF-1",
    color: "text-blue-400 border-blue-700/50 bg-blue-950/30",
    dot: "bg-blue-400",
    allowed: ["APP→WEB allowed (one-way)", "Inbound from internet via LEAF-1"],
    blocked: ["WEB→DB (microseg BLOCK)", "WEB→MGT (BLOCK)"],
  },
  {
    name: "DB",
    subnet: "10.1.200.0/24",
    host: "Alpine-2",
    ip: "10.1.200.2",
    leaf: "LEAF-1",
    color: "text-red-400 border-red-700/50 bg-red-950/30",
    dot: "bg-red-400",
    allowed: ["APP→DB allowed"],
    blocked: ["DB outbound any (BLOCK)", "WEB→DB (BLOCK)"],
  },
  {
    name: "APP",
    subnet: "10.2.100.0/24",
    host: "Alpine-3",
    ip: "10.2.100.2",
    leaf: "LEAF-2",
    color: "text-purple-400 border-purple-700/50 bg-purple-950/30",
    dot: "bg-purple-400",
    allowed: ["APP→WEB", "APP→DB"],
    blocked: ["APP→MGT (BLOCK)", "APP→WEB reverse call (BLOCK)"],
  },
  {
    name: "MGT",
    subnet: "10.2.50.0/24",
    host: "Alpine-5",
    ip: "10.2.50.2",
    leaf: "LEAF-2",
    color: "text-yellow-400 border-yellow-700/50 bg-yellow-950/30",
    dot: "bg-yellow-400",
    allowed: ["MGT→any (management only)"],
    blocked: ["WEB→MGT (BLOCK)", "APP→MGT (BLOCK)"],
  },
];

const policies = [
  { from: "WEB", to: "DB", action: "BLOCK", priority: 1, sid: "9000001", desc: "Microsegmentation bypass" },
  { from: "DB", to: "ANY", action: "BLOCK", priority: 1, sid: "9000002", desc: "DB outbound prohibited" },
  { from: "APP", to: "WEB", action: "ALERT", priority: 2, sid: "9000003", desc: "Lateral movement" },
  { from: "WEB", to: "MGT", action: "ALERT", priority: 2, sid: "9000004", desc: "Unauthorized access" },
  { from: "APP", to: "MGT", action: "ALERT", priority: 2, sid: "9000005", desc: "Unauthorized access" },
];

export default function TopologyPage() {
  return (
    <main className="min-h-screen bg-tc-darker pt-20">
      <div className="mx-auto max-w-6xl px-6 py-10">
        <ScrollReveal>
          <div className="mb-2 inline-flex items-center rounded-full border border-tc-green/20 bg-tc-green/5 px-4 py-1.5 text-xs font-mono text-tc-green">
            GNS3 · SONiC-VS · tc mirred TAP
          </div>
          <h1 className="mt-3 text-3xl font-bold text-white">Network Topology</h1>
          <p className="mt-2 text-sm text-tc-text-dim">
            Spine-Leaf DC Fabric với Zero Trust microsegmentation và IDS monitoring
          </p>
        </ScrollReveal>

        {/* Topology Diagram */}
        <ScrollReveal delay={100}>
          <div className="mt-8 rounded-xl border border-tc-border bg-tc-card p-6 font-mono text-sm overflow-x-auto">
            <div className="min-w-[560px]">
              {/* Internet / Cloud */}
              <div className="flex justify-center mb-2">
                <div className="rounded border border-tc-border/50 bg-tc-darker px-4 py-1.5 text-xs text-tc-text-dim">
                  🌐 Internet / Cloud Node (virbr0 192.168.122.x)
                </div>
              </div>
              <div className="flex justify-center mb-2">
                <div className="w-px h-4 bg-tc-border" />
              </div>

              {/* SPINE */}
              <div className="flex justify-center mb-2">
                <div className="rounded-lg border border-tc-green/40 bg-tc-green/5 px-8 py-2 text-tc-green font-bold text-sm glow-box">
                  ⚡ SONIC-SPINE (SONiC-VS)
                </div>
              </div>

              {/* SPINE → LEAF lines */}
              <div className="flex justify-center gap-32 mb-1 text-tc-border text-lg">
                <span className="translate-x-4">╱</span>
                <span className="-translate-x-4">╲</span>
              </div>

              {/* LEAFs row */}
              <div className="flex justify-center gap-16 mb-2">
                <div className="rounded-lg border border-tc-border bg-tc-card/80 px-6 py-2 text-center">
                  <div className="text-white font-bold text-xs mb-0.5">LEAF-1</div>
                  <div className="text-tc-text-dim text-xs">10.0.0.2</div>
                  <div className="text-tc-green text-xs mt-1">↓ tc mirred → IDS eth0</div>
                </div>
                <div className="rounded-lg border border-tc-border bg-tc-card/80 px-6 py-2 text-center">
                  <div className="text-white font-bold text-xs mb-0.5">LEAF-2</div>
                  <div className="text-tc-text-dim text-xs">10.0.0.4</div>
                  <div className="text-tc-green text-xs mt-1">↓ tc mirred → IDS eth1</div>
                </div>
              </div>

              {/* Host nodes */}
              <div className="flex justify-center gap-4 mb-4">
                {/* LEAF-1 hosts */}
                <div className="flex flex-col gap-2">
                  <div className="rounded border border-blue-700/40 bg-blue-950/20 px-3 py-1.5 text-center">
                    <div className="text-blue-400 text-xs font-bold">Alpine-1</div>
                    <div className="text-tc-text-dim text-xs">WEB · 10.1.100.2</div>
                  </div>
                  <div className="rounded border border-red-700/40 bg-red-950/20 px-3 py-1.5 text-center">
                    <div className="text-red-400 text-xs font-bold">Alpine-2</div>
                    <div className="text-tc-text-dim text-xs">DB · 10.1.200.2</div>
                  </div>
                </div>

                {/* IDS in center */}
                <div className="flex flex-col items-center justify-center">
                  <div className="rounded-lg border border-tc-green/60 bg-tc-green/10 px-4 py-3 text-center glow-box">
                    <div className="text-tc-green font-bold text-xs">🛡️ IDS-Suricata</div>
                    <div className="text-tc-text-dim text-xs">Alpine Linux</div>
                    <div className="text-tc-text-dim text-xs">eth0 ← LEAF-1</div>
                    <div className="text-tc-text-dim text-xs">eth1 ← LEAF-2</div>
                    <div className="text-tc-green text-xs mt-1">eth2 → virbr0</div>
                    <div className="text-tc-green text-xs">API :8765</div>
                  </div>
                </div>

                {/* LEAF-2 hosts */}
                <div className="flex flex-col gap-2">
                  <div className="rounded border border-purple-700/40 bg-purple-950/20 px-3 py-1.5 text-center">
                    <div className="text-purple-400 text-xs font-bold">Alpine-3</div>
                    <div className="text-tc-text-dim text-xs">APP · 10.2.100.2</div>
                  </div>
                  <div className="rounded border border-yellow-700/40 bg-yellow-950/20 px-3 py-1.5 text-center">
                    <div className="text-yellow-400 text-xs font-bold">Alpine-5</div>
                    <div className="text-tc-text-dim text-xs">MGT · 10.2.50.2</div>
                  </div>
                </div>
              </div>

              {/* Web App connection */}
              <div className="flex justify-center mt-2">
                <div className="text-xs text-tc-text-dim">
                  IDS eth2 → virbr0 → NAT →{" "}
                  <span className="text-tc-green">112.137.129.232:8765</span> → Web App (ONAP SDNC)
                </div>
              </div>
            </div>
          </div>
        </ScrollReveal>

        {/* Zone Cards */}
        <ScrollReveal delay={200}>
          <h2 className="mt-10 mb-4 text-lg font-bold text-white">Microsegment Zones</h2>
        </ScrollReveal>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {zones.map((z, i) => (
            <ScrollReveal key={z.name} delay={i * 80 + 200}>
              <div className={`rounded-xl border p-5 ${z.color}`}>
                <div className="flex items-center gap-2 mb-3">
                  <span className={`w-2 h-2 rounded-full ${z.dot}`} />
                  <span className="font-bold text-white font-mono">{z.name}</span>
                  <span className="text-xs font-mono opacity-70">{z.subnet}</span>
                </div>
                <div className="text-xs font-mono mb-3 opacity-80">
                  {z.host} · {z.ip} · via {z.leaf}
                </div>
                <div className="space-y-1">
                  {z.allowed.map((r) => (
                    <div key={r} className="text-xs flex items-start gap-1.5">
                      <span className="text-tc-green mt-0.5">✓</span>
                      <span className="text-tc-text-dim">{r}</span>
                    </div>
                  ))}
                  {z.blocked.map((r) => (
                    <div key={r} className="text-xs flex items-start gap-1.5">
                      <span className="text-red-400 mt-0.5">✗</span>
                      <span className="text-tc-text-dim">{r}</span>
                    </div>
                  ))}
                </div>
              </div>
            </ScrollReveal>
          ))}
        </div>

        {/* Policy Matrix */}
        <ScrollReveal delay={400}>
          <h2 className="mt-10 mb-4 text-lg font-bold text-white">IDS Detection Policies</h2>
          <div className="rounded-xl border border-tc-border bg-tc-card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-tc-border text-xs font-mono text-tc-text-dim">
                    <th className="px-4 py-3 text-left">From</th>
                    <th className="px-4 py-3 text-left">To</th>
                    <th className="px-4 py-3 text-left">Action</th>
                    <th className="px-4 py-3 text-left">SID</th>
                    <th className="px-4 py-3 text-left">Description</th>
                  </tr>
                </thead>
                <tbody>
                  {policies.map((p) => (
                    <tr key={p.sid} className="border-b border-tc-border/50 hover:bg-tc-green/5 transition-colors">
                      <td className="px-4 py-3 font-mono text-xs font-bold text-white">{p.from}</td>
                      <td className="px-4 py-3 font-mono text-xs text-tc-text-dim">{p.to}</td>
                      <td className="px-4 py-3">
                        <span
                          className={`px-2 py-0.5 rounded text-xs font-mono font-bold border ${
                            p.action === "BLOCK"
                              ? "bg-red-900/40 text-red-400 border-red-700/40"
                              : "bg-orange-900/40 text-orange-400 border-orange-700/40"
                          }`}
                        >
                          {p.action}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-tc-text-dim">{p.sid}</td>
                      <td className="px-4 py-3 text-xs text-tc-text-dim">{p.desc}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </ScrollReveal>
      </div>
    </main>
  );
}
