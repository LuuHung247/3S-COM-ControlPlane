# Prompt forward cho DATAPLANE agent — fix 3 controller V2 không fire Suricata

> Bối cảnh: chạy thực nghiệm paper Q1 trên fabric V2. 2/5 real-traffic OK (S01 WEB→DB-OLTP,
> S07 DB-OLTP→C2). **3 cái controller ARM được nhưng Suricata KHÔNG fire SID** → agent
> không nhận alert nào trong 120s (`outcome=none`). Đây là phía dataplane (traffic không
> khớp rule / cron không chạy), KHÔNG phải agent. Cần verify + fix trên GNS3/Suricata.

Console MGT: telnet `10.10.6.238:5016`. Controllers ở `/root/scenario/v2/`.

## 1. S04 — `compromise-v2-appcore-dba-exfil.sh` (SID 9000070 content-match)
- Mong đợi: APP-CORE(10.2.100.10)→DB-ANLT(10.3.200.10:5432) gửi bulk SQL `UNION SELECT` →
  Suricata DPI fire **SID 9000070** ("SQL syntax — UNION SELECT"). Hiện không fire.
- **Cần kiểm tra:** payload controller có chứa đúng pattern pcre của rule 9000070 không
  (chạy `sh /root/scenario/v2/compromise-v2-appcore-dba-exfil.sh` rồi xem `tail -f` eve.json
  trên IDS có alert 9000070 không). Content-match cần payload thật khớp regex, không chỉ
  mở connection. Verify rule 9000070 enabled trong suricata-zt.yaml.

## 2. S05 — `compromise-v2-appcore-reverse.sh` (SID 9000006 single-packet)
- Mong đợi: APP-CORE(10.2.100.10)→WEB(10.1.100.10:22) một SYN SSH ngược tier →
  **SID 9000006** fire ngay packet đầu (không threshold). Hiện không fire.
- **Cần kiểm tra:** controller có thật sự phát SYN tới 10.1.100.10:22 không (flag file +
  cron tick?), hay đang no-op. Verify rule 9000006 match `dst_port:22` + hướng đúng.

## 3. S10 — baseline FP (SID 9000080/9000081, passive)
- Mong đợi: cron baseline MGT(10.2.50.10, mỗi ~2min, SID 9000080) + MON(10.4.200.10,
  mỗi ~60s, SID 9000081) tự fire → agent log_only. Hiện 120s không có alert nào.
- **Cần kiểm tra:** cron baseline trên MGT/MON host còn chạy không (`crontab -l`), và rule
  9000080/9000081 còn enabled không. Nếu cron bị gỡ khi rebuild Alpine ISO (tmpfs wipe) →
  cần re-add vào `/etc/local.d/` hoặc startup script.

## Verify chung
Sau khi fix mỗi cái: chạy controller → `tail` eve.json trên IDS xem SID đúng fire →
báo lại. Khi đó mình chạy lại 3 scenario này từ harness là ra kết quả.
