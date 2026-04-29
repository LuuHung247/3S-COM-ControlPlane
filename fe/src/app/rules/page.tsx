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
  {
    sid: 9000003,
    priority: 2,
    category: "Lateral Movement",
    name: "APP reverse call to WEB – lateral movement",
    from: "APP (10.2.100.0/24)",
    to: "WEB (10.1.100.0/24)",
    proto: "IP",
    desc: "APP tier không nên gọi ngược lại WEB tier. Flow chuẩn là WEB→APP, không phải ngược lại. Reverse call là dấu hiệu lateral movement hoặc C2 callback.",
  },
  {
    sid: 9000004,
    priority: 2,
    category: "Lateral Movement",
    name: "WEB to MGT – unauthorized access",
    from: "WEB (10.1.100.0/24)",
    to: "MGT (10.2.50.0/24)",
    proto: "IP",
    desc: "WEB tier không có quyền truy cập management network. Bất kỳ kết nối WEB→MGT nào đều là unauthorized access, có thể là privilege escalation.",
  },
  {
    sid: 9000005,
    priority: 2,
    category: "Lateral Movement",
    name: "APP to MGT – unauthorized access",
    from: "APP (10.2.100.0/24)",
    to: "MGT (10.2.50.0/24)",
    proto: "IP",
    desc: "Application tier không được phép truy cập management zone. Phát hiện kết nối này là dấu hiệu compromised application hoặc insider threat.",
  },
  {
    sid: 9000006,
    priority: 1,
    category: "Lateral Movement",
    name: "APP direct to DB – lateral movement (SC-3b)",
    from: "APP (10.2.100.0/24)",
    to: "DB (10.1.200.0/24)",
    proto: "IP",
    desc: "Phát hiện APP tier kết nối trực tiếp tới DB mà không qua authorized path. Đây là multi-hop lateral movement (SC-3b): attacker đã compromise APP node và đang cố exfiltrate data từ DB subnet.",
  },
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
