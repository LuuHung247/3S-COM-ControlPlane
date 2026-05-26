# 13 kịch bản thực nghiệm — bản thuyết trình

> Bản mô tả bằng lời cho từng scenario S1–S13: tình huống tấn công, hành vi cụ thể
> trên hạ tầng, **quy tắc nào bị vi phạm** (policy matrix Zero Trust + Suricata
> rule), và **quyết định mong đợi** của agent. Dùng cho slide / nói khi demo.
>
> Ma trận policy gốc (zone DENY/ALLOW theo hướng):
>
> | Source ↓ \ Destination → | WEB | DB | APP | MGT |
> |---|---|---|---|---|
> | **WEB** | — | DENY | ALLOW | DENY |
> | **DB**  | DENY | — | DENY | DENY |
> | **APP** | DENY | ALLOW | — | DENY |
> | **MGT** | ALLOW | ALLOW | ALLOW | — |
>
> Host: WEB `10.1.100.10` · DB `10.1.200.10` · APP `10.2.100.10` · MGT `10.2.50.10`.

---

## Nhóm 1 — Vi phạm phân đoạn nội bộ (ZT microsegmentation)

### S1 · WEB → DB lateral movement

**Tình huống.** Tin tặc đã chiếm được web server (10.1.100.10) — có thể qua lỗ hổng
web nào đó. Thay vì đi theo luồng hợp lệ WEB→APP→DB, nó **nhảy thẳng tới database
10.1.200.10:5432** để truy vấn PostgreSQL trực tiếp. Đây là bước **lateral movement
kinh điển** tới crown jewel.

**Vi phạm.** Policy matrix nói **WEB→DB = DENY**. Mọi kết nối trực tiếp dạng này đều
là vi phạm phân đoạn (microsegmentation bypass) — bỏ qua tầng application vốn được
thiết kế để kiểm soát truy vấn.

**Suricata bắn.** **SID 9000001** *"[ZT-VIOLATION] WEB direct to DB —
microsegmentation bypass"* · **Priority 1 (Critical)** · MITRE TA0008 / T1021.

**Kỳ vọng agent.** Quyết định **DROP** chặn 10.1.100.10/32, TTL 3600s. Rule áp lên
LEAF-1 (zone WEB+DB).

---

### S2 · WEB → APP burst (đường hợp lệ bị lạm dụng)

**Tình huống.** Web server bị nhiễm botnet, mở **hàng trăm kết nối liên tục** tới
APP server 10.2.100.10:8080 chỉ trong vài giây. Đường WEB→APP **được cho phép** —
đây là bị abuse cường độ, không phải vi phạm phân đoạn.

**Vi phạm.** Policy WEB→APP = ALLOW nên không vi phạm phân đoạn. Nhưng tần suất
SYN vượt ngưỡng baseline (proxy thường ~120 req/h, attack >5 req/60s).

**Suricata bắn.** **SID 9000041** *"[ZT-RECON] TCP probe on key service ports"* ·
**Priority 3** · ngưỡng 5/60s.

**Kỳ vọng agent.** Trên ngưỡng P3 → mặc định **log_only**. Agent có thể nâng lên
DROP nếu so baseline thấy cường độ thật sự bất thường, hoặc giữ log_only để tránh
chặn nhầm traffic hợp lệ.

---

### S3 · APP → DB burst (data exfiltration cường độ cao)

**Tình huống.** Application server (10.2.100.10) bị chiếm — kẻ tấn công dùng quyền
hợp lệ APP→DB để **bùng hàng nghìn kết nối/giây** tới DB:5432. Goal: kéo data ra
càng nhanh càng tốt trước khi bị phát hiện.

**Vi phạm.** Đường APP→DB hợp lệ về phân đoạn, nhưng tốc độ vượt baseline OLTP
nghiêm trọng (>200 SYN/10s từ 1 nguồn).

**Suricata bắn.** **SID 9000043** *"[ZT-FLOOD] TCP SYN flood — sustained high rate
from single source"* · **Priority 2 (High)** · ngưỡng 200/10s.

**Kỳ vọng agent.** Quyết định **DROP** 10.2.100.10/32 vì cường độ vượt baseline xa.
Đây là ca **đường hợp lệ bị abuse** — chỉ agent reasoning + baseline matching mới
phân biệt được hợp lệ vs lạm dụng.

---

### S4 · APP → DB destructive SQL (phá hoại dữ liệu)

**Tình huống.** APP đã bị chiếm và gửi lệnh **`DROP TABLE`**, **`TRUNCATE`**, hoặc
**`DELETE FROM`** xuống DB. Đây là tấn công **phá hoại trực tiếp** — không lấy
data, mà xóa data.

**Vi phạm.** Đường APP→DB hợp lệ về kết nối, nhưng nội dung payload chứa lệnh phá
hoại. Phát hiện bằng deep-packet content matching (pcre).

**Suricata bắn.** **SID 9000050** *"[ZT-CONTENT] Destructive SQL statement in DB
stream"* · **Priority 1 (Critical)** · pcre match `DROP TABLE|TRUNCATE|DELETE FROM`.

**Kỳ vọng agent.** **DROP ngay 10.2.100.10/32** + escalate. Đây là P1 không có chỗ
cho log_only — mất 1 bảng = mất sản phẩm.

---

### S5 · APP → MGT SSH (cố leo thang quyền)

**Tình huống.** Sau khi chiếm APP, kẻ tấn công thử **SSH lên máy quản trị**
(MGT 10.2.50.10:22) để leo thang quyền — mục tiêu lấy credential admin / config.

**Vi phạm.** Policy matrix: **APP→MGT = DENY** (chỉ MGT mới được initiate kết nối
xuống các zone, không có chiều ngược). Đây là vi phạm phân đoạn cross-tier rõ ràng.

**Suricata bắn.** **SID 9000005** *"[ZT-ALERT] APP to MGT — unauthorized access"* ·
**Priority 2 (High)** · port 22/3389.

**Kỳ vọng agent.** **DROP** 10.2.100.10/32. Mặc dù `zt-default-drop` ở LEAF cũng đã
chặn ở L3, agent vẫn phải push rule có TTL để **flag host** cho điều tra (host này
đã bị compromise).

---

## Nhóm 2 — NetVigil benchmark (8 lớp tấn công mạng tổng quát)

> Adapted from NetVigil NSDI'24 Table 3. Mỗi ca đại diện 1 lớp pattern tấn công.

### S6 · Vertical port scan (trinh sát theo chiều dọc)

**Tình huống.** APP đã bị chiếm — kẻ tấn công bắt đầu **quét rất nhiều port trên
1 host duy nhất** (vd DB) để tìm dịch vụ chưa được bảo vệ. "Vertical" = nhiều port,
ít host.

**Vi phạm.** Tốc độ probe vượt ngưỡng baseline (>20 port/30s từ 1 nguồn).

**Suricata bắn.** **SID 9000040** *"[ZT-RECON] Vertical port scan — many ports same
destination"* · **Priority 3 (Info)** · ngưỡng 20/30s.

**Kỳ vọng agent.** Mặc định **log_only** (P3, chưa phải attack chính). Có thể nâng
DROP nếu thấy host đã được flag trước.

---

### S7 · SYN flood DoS (1 nguồn)

**Tình huống.** APP bị chiếm, **flood TCP SYN dồn dập** tới DB:5432 — mục tiêu
exhausting connection queue, DoS service. >200 SYN/giây từ 1 IP.

**Vi phạm.** Single-source DoS — cường độ vượt ngưỡng baseline.

**Suricata bắn.** **SID 9000043** *"[ZT-FLOOD] TCP SYN flood — sustained high rate
from single source"* · **Priority 2** · ngưỡng 200/10s.

**Kỳ vọng agent.** **DROP** 10.2.100.10/32 — DoS thì rate-limit không đủ, phải
chặn nguồn.

---

### S8 · Distributed SYN flood (DDoS)

**Tình huống.** Botnet — **2 host cùng tấn công** DB:5432 đồng thời (APP +
WEB phối hợp), mỗi host gửi rate vừa phải nên không hit ngưỡng single-source, nhưng
**tổng combined** đủ DoS. Đây là phiên bản phân tán của S7.

**Vi phạm.** Distributed DoS — mỗi nguồn 1 phần, agent phải **correlate per-src
signal**.

**Suricata bắn.** **SID 9000044** *"[ZT-FLOOD] TCP SYN contribution from source"* ·
**Priority 2** · threshold by_both (theo cặp src→dst).

**Kỳ vọng agent.** **DROP cả 2 attacker IP** (10.1.100.10 + 10.2.100.10). Agent
phải hiểu đây là 1 cuộc tấn công duy nhất chứ không phải 2 sự cố lẻ.

---

### S9 · UDP flood (amplification / availability attack)

**Tình huống.** WEB bị chiếm, **flood UDP rate cao** tới DB:53 (DNS) — có thể là
amplification attack hoặc đơn giản exhaust bandwidth của victim.

**Vi phạm.** Cường độ UDP vượt baseline (>500 packets/10s tới 1 dst).

**Suricata bắn.** **SID 9000045** *"[ZT-FLOOD] UDP packet flood — high rate to
destination"* · **Priority 2** · ngưỡng by_dst 500/10s.

**Kỳ vọng agent.** **DROP** 10.1.100.10/32. Khác TCP — UDP không có handshake nên
flood tác động ngay.

---

### S10 · Distributed scan (trinh sát phân tán)

**Tình huống.** **2 host cùng quét** key service port (telnet, http, mysql, RDP,
MS-SQL…) trên nhiều dst host. Phân tán để né per-source threshold của recon
detector.

**Vi phạm.** Mỗi nguồn chỉ vài probe — đơn lẻ thì không lên ngưỡng. **Phải
correlate**.

**Suricata bắn.** **SID 9000041** *"[ZT-RECON] TCP probe on key service ports"* ·
**Priority 3** · ngưỡng 5/60s per source.

**Kỳ vọng agent.** **log_only** ở P3, hoặc DROP nếu reasoning + memory ghép được
nhiều source attack đồng thời → kết luận đây là chiến dịch.

---

### S11 · Multi-stage propagation (worm-like lateral spread)

**Tình huống.** APP bị chiếm — kẻ tấn công triển khai **infection monkey**: scan
trước, sau đó probe các port "thường bị khai thác" (telnet 23, NetBIOS 135/139/445,
RDP 3389, HTTPS-alt 8443) để tìm máy khác để chiếm tiếp. Hành vi worm điển hình.

**Vi phạm.** Probe port nguy hiểm + nhiều host = lateral propagation chain.

**Suricata bắn.** **SID 9000052** *"[ZT-RECON] Probe on commonly-exploited service
port"* · **Priority 3** · ngưỡng 10/60s.

**Kỳ vọng agent.** **DROP** 10.2.100.10/32 + flag host (đã bắt đầu lan, phải dập
nguồn ngay). Agent có thể correlate với S6 (scan trước đó cùng IP) để raise severity.

---

### S12 · C2 beacon (heartbeat ra C2 server)

**Tình huống.** APP đã bị nhiễm malware — định kỳ gửi **gói nhỏ ra ngoài internet**
(8.8.8.8:443) báo về cho C2 (command-and-control) server. Mục đích: chờ lệnh từ kẻ
tấn công. Kỳ jitter ~30s, payload <200B, **rất giống traffic bình thường** → đây
là ca khó nhất trong benchmark.

**Vi phạm.** Đường ra ngoài hợp lệ về policy nhưng **pattern bất thường**: periodic
+ small payload + low jitter.

**Suricata bắn.** **SID 9000046** *"[ZT-BEACON] Periodic small outbound — possible
C2 heartbeat"* · **Priority 2** · dsize<200, threshold 3/90s.

**Kỳ vọng agent.** **DROP** 10.2.100.10/32 → 8.8.8.8:443. Đây là ca *paper-aligned*:
NetVigil đạt AUC 0.93, Kitsune+ chỉ 0.63 — chứng tỏ pattern khó nhận. Agent giải
được nhờ context reasoning + baseline deviation.

---

### S13 · Unauthorized DB access (truy cập DB từ zone lạ)

**Tình huống.** Một máy không phải APP (vd WEB) **kết nối thẳng tới DB** (PostgreSQL,
MySQL, MS-SQL, MongoDB). Đây là dạng tổng quát của S1 — không nhất thiết WEB, có
thể là MGT bị compromise, hoặc 1 host lạ mới được provision bất hợp pháp.

**Vi phạm.** **Mọi zone không phải APP đều DENY** với DB ports.

**Suricata bắn.** **SID 9000051** *"[ZT-VIOLATION] DB connection from non-APP zone"* ·
**Priority 1 (Critical)** · negation pattern `!APP zone`.

**Kỳ vọng agent.** **DROP** nguồn ngay (10.1.100.10/32 hoặc bất kỳ IP nào không phải
APP zone).

---

## Phụ chú khi thuyết trình

**Vì sao 1 attack đôi khi nổ nhiều SID?** Suricata có **defense-in-depth ở mức
detection** — vd WEB→DB direct trùng cả **SID 9000001** (rule cụ thể WEB→DB) và
**SID 9000051** (rule tổng quát "non-APP→DB"). Mục đích: 1 rule miss thì rule khác
bắt. Agent xử lý mỗi alert độc lập (giữ audit đầy đủ) nhưng có rate-limiter L5 chống
spam rule chồng chéo.

**Vì sao có ca log_only?** Vì policy zone của chính ca đó là ALLOW (S2 WEB→APP,
S10 distributed scan). Detection chỉ là "cảnh báo cường độ", không phải vi phạm
phân đoạn → mặc định log để theo dõi, không tự ý chặn (tránh false-positive làm
gián đoạn dịch vụ thật).

**Vì sao agent vẫn cần thiết dù LEAF đã `zt-default-drop`?** Default-drop chặn
cross-zone DENY ở L3 — đúng. Nhưng:
1. Đường **ALLOW bị abuse** (S2, S3, S12) — LEAF cho qua, chỉ agent + baseline mới
   phát hiện được.
2. **Per-IP attribution + TTL** — agent push rule có scope hẹp (1 IP /32) thay vì
   chặn cả zone, có TTL tự xoá. Default-drop không làm được.
3. **Correlate đa nguồn** (S8 DDoS, S10 distributed) — chỉ agent reasoning mới ghép
   được nhiều IP thành 1 chiến dịch.

**Demo cách trả lời "tại sao 12s thay vì rule ms?"**
Phần thực nghiệm bổ sung (S14 + S15 trong [docs/extended_evaluation_report.md](../../docs/extended_evaluation_report.md))
trả lời 2 nửa câu hỏi đó: S14 chứng minh kiến trúc safety chặn 100% adversarial
input (vs 100% violation của vanilla LLM), S15 chứng minh agent generalize tới
SID lạ (67% vs 0% của SOAR signature-keyed).
