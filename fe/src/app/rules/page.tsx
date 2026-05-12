import ScrollReveal from "@/components/ScrollReveal";

const rules = [
  {
    sid: 9000001,
    priority: 1,
    category: "Policy Violation",
    name: "WEB direct to DB – microsegmentation bypass",
    from: "WEB (10.1.100.0/24)",
    to: "DB (10.1.200.0/24)",
    proto: "IP",
    desc: "Phát hiện kết nối trực tiếp từ WEB zone sang DB zone, vi phạm nguyên tắc microsegmentation. Trong kiến trúc ZT, WEB chỉ được nói chuyện qua APP tier.",
  },
  {
    sid: 9000002,
    priority: 1,
    category: "Policy Violation",
    name: "DB initiating outbound connection",
    from: "DB (10.1.200.0/24)",
    to: "ANY (ngoài DB subnet)",
    proto: "IP",
    desc: "DB server không được phép khởi tạo kết nối ra ngoài. Chỉ nhận kết nối từ APP tier. Phát hiện kết nối outbound từ DB là dấu hiệu data exfiltration hoặc lateral movement.",
  },
  // SIDs 9000003 / 9000004 / 9000005 removed in 2026-05-09 refactor — all three
  // fire on DENY paths that LEAF default-drop already handles. Replaced with
  // ALLOW-path anomaly SIDs (9000030–9000035) where the agent is the essential layer.
  {
    sid: 9000010,
    priority: 3,
    category: "Reconnaissance",
    name: "ICMP ping sweep detected",
    from: "ANY",
    to: "ANY",
    proto: "ICMP",
    desc: "Threshold: 3 ICMP Echo Request trong 10 giây từ cùng source. Dấu hiệu network reconnaissance / host discovery scan.",
  },
  {
    sid: 9000011,
    priority: 3,
    category: "Reconnaissance",
    name: "Possible port scan",
    from: "ANY",
    to: "ANY",
    proto: "TCP SYN",
    desc: "Threshold: 10 SYN packets trong 5 giây từ cùng source. Dấu hiệu port scanning (nmap, masscan) để tìm kiếm dịch vụ mở.",
  },
  {
    sid: 9000020,
    priority: 4,
    category: "Audit",
    name: "Management zone access",
    from: "MGT (10.2.50.0/24)",
    to: "ANY",
    proto: "IP",
    desc: "Audit log: mỗi kết nối từ MGT zone được ghi lại (1 lần/phút/source). Phục vụ compliance và traceability cho tất cả management actions.",
  },
  // ── East-West Behavioral Anomalies (ALLOW-path abuse — agent essential) ──
  {
    sid: 9000030,
    priority: 2,
    category: "East-West Volumetric",
    name: "WEB→APP rate burst (compromised web-tier?)",
    from: "WEB (10.1.100.0/24)",
    to: "APP (10.2.100.0/24):8080",
    proto: "TCP SYN",
    desc: "Threshold: >200 conn/min/src (baseline ~60/min). Flow ALLOWED bởi LEAF zt-web-app-allow nên iptables không chặn — agent là layer duy nhất detect rate anomaly trong legitimate path.",
  },
  {
    sid: 9000031,
    priority: 2,
    category: "East-West Volumetric",
    name: "APP→DB volume anomaly (possible exfiltration)",
    from: "APP (10.2.100.0/24)",
    to: "DB (10.1.200.0/24):5432",
    proto: "TCP SYN",
    desc: "Threshold: >100 conn/min/src (baseline ~60/min). ALLOW path nên LEAF accept. Compromised app-01 abusing DB grant cho bulk extraction — canonical scenario cho agent essential.",
  },
  {
    sid: 9000032,
    priority: 2,
    category: "East-West Volumetric",
    name: "DB large reply payload (bulk SELECT)",
    from: "DB (10.1.200.0/24):5432",
    to: "APP (10.2.100.0/24)",
    proto: "TCP",
    desc: "Reply payload >4KB lặp lại ≥10 lần trong 30s. Normal reply ~100 bytes. Bulk SELECT / JOIN extraction signal — agent decide block targeted hay escalate human.",
  },
  {
    sid: 9000033,
    priority: 1,
    category: "East-West Semantic",
    name: "Destructive SQL pattern (DROP TABLE / TRUNCATE)",
    from: "APP (10.2.100.0/24)",
    to: "DB (10.1.200.0/24):5432",
    proto: "TCP content",
    desc: "Content match DROP TABLE hoặc TRUNCATE trong APP→DB traffic. APP không bao giờ được phép schema-destructive. Incident-grade — agent DROP targeted + escalate SOC.",
  },
  {
    sid: 9000034,
    priority: 3,
    category: "East-West Context",
    name: "APP→DB time-window probe (agent evaluates)",
    from: "APP (10.2.100.0/24)",
    to: "DB (10.1.200.0/24):5432",
    proto: "TCP SYN",
    desc: "Throttled 1/5min/src. Always-fire probe. Agent kiểm time-of-day: business hours (08-18 UTC) → log_only; off-hours với corroborating signal → DROP. Suricata không native time-based.",
  },
  {
    sid: 9000035,
    priority: 1,
    category: "Lateral Movement",
    name: "Cross-tier SSH (workload→workload)",
    from: "WEB / APP",
    to: "WEB / APP / DB:22",
    proto: "TCP SYN",
    desc: "Workload-to-workload SSH không bao giờ legit — chỉ MGT mới được SSH vào workloads. Strong indicator of compromise pivot. Agent DROP targeted + flag host suspicious.",
  },
];

const PRIORITY_STYLE: Record<number, string> = {
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

export default function RulesPage() {
  return (
    <main className="min-h-screen bg-tc-darker pt-20">
      <div className="mx-auto max-w-6xl px-6 py-10">
        <ScrollReveal>
          <div className="mb-2 inline-flex items-center rounded-full border border-tc-green/20 bg-tc-green/5 px-4 py-1.5 text-xs font-mono text-tc-green">
            Suricata 8.0 · 3s-nos.rules · 9 rules loaded
          </div>
          <h1 className="mt-3 text-3xl font-bold text-white">Detection Rules</h1>
          <p className="mt-2 text-sm text-tc-text-dim max-w-2xl">
            9 Suricata rules phát hiện vi phạm chính sách Zero Trust. Được nhóm theo category:
            Policy Violation (P1), Lateral Movement (P2), Reconnaissance (P3), và Audit (P4).
          </p>
        </ScrollReveal>

        {/* Stats */}
        <ScrollReveal delay={100}>
          <div className="mt-6 grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
            {[
              { label: "Total Rules", value: "9", color: "text-white" },
              { label: "P1 Critical", value: "3", color: "text-red-400" },
              { label: "P2 High", value: "3", color: "text-orange-400" },
              { label: "P3+P4", value: "3", color: "text-yellow-400" },
            ].map((s) => (
              <div key={s.label} className="rounded-xl border border-tc-border bg-tc-card px-4 py-3 text-center">
                <div className={`text-xl font-bold font-mono ${s.color}`}>{s.value}</div>
                <div className="text-xs text-tc-text-dim mt-1">{s.label}</div>
              </div>
            ))}
          </div>
        </ScrollReveal>

        {/* Rules list */}
        <div className="space-y-4">
          {rules.map((rule, i) => (
            <ScrollReveal key={rule.sid} delay={i * 60}>
              <div className="rounded-xl border border-tc-border bg-tc-card p-5 transition-all hover:border-tc-green/30 glow-box-hover">
                <div className="flex flex-wrap items-start justify-between gap-3 mb-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`px-2 py-0.5 rounded border text-xs font-mono font-bold ${PRIORITY_STYLE[rule.priority]}`}
                    >
                      {PRIORITY_LABEL[rule.priority]}
                    </span>
                    <span className="rounded border border-tc-border px-2 py-0.5 text-xs font-mono text-tc-text-dim">
                      {rule.category}
                    </span>
                    <span className="rounded bg-tc-darker px-2 py-0.5 text-xs font-mono text-tc-green border border-tc-green/20">
                      SID:{rule.sid}
                    </span>
                  </div>
                  <span className="text-xs font-mono text-tc-text-dim border border-tc-border/50 rounded px-2 py-0.5">
                    proto: {rule.proto}
                  </span>
                </div>

                <h3 className="font-bold text-white mb-2 text-sm">{rule.name}</h3>

                <div className="flex flex-wrap gap-x-6 gap-y-1 mb-3 text-xs font-mono">
                  <span>
                    <span className="text-tc-text-dim">from: </span>
                    <span className="text-tc-green">{rule.from}</span>
                  </span>
                  <span>
                    <span className="text-tc-text-dim">to: </span>
                    <span className="text-tc-green">{rule.to}</span>
                  </span>
                </div>

                <p className="text-sm text-tc-text-dim leading-relaxed">{rule.desc}</p>
              </div>
            </ScrollReveal>
          ))}
        </div>

        {/* Raw rule file reference */}
        <ScrollReveal delay={500}>
          <div className="mt-8 rounded-xl border border-tc-border/50 bg-tc-darker p-4 font-mono text-xs text-tc-text-dim">
            <div className="text-tc-green mb-2"># Rule file location on IDS node:</div>
            <div>/etc/suricata/rules/3s-nos.rules</div>
            <div className="mt-2 text-tc-green"># Config:</div>
            <div>/etc/suricata/suricata-zt.yaml</div>
            <div className="mt-2 text-tc-green"># Logs:</div>
            <div>/var/log/suricata/eve.json  (JSON alerts)</div>
            <div>/var/log/suricata/fast.log  (human-readable)</div>
          </div>
        </ScrollReveal>
      </div>
    </main>
  );
}
