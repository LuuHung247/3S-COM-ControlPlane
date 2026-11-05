# BIZM — Computer Networks revision: việc cần hoàn thiện

**"BIZM: Verification-Guided LLM Response Synthesis for Bounded East–West Threat Containment in Zero-Trust Microsegmentation"**.
Mọi chỗ cần số liệu từ thực nghiệm bổ sung được đánh dấu **chữ đỏ** bằng macro `\red{...}` (đoạn văn) và `\tbd` (ô bảng). Trước khi nộp, xoá hoặc vô hiệu hai macro này ở đầu file.

Tất cả số liệu cũ của nhóm được giữ nguyên; hai agent đã kiểm tra lại toàn bộ số liệu tính được (kích thước miền 136.080; 19.824 = 14.970 + 822 + 4.032; mọi khoảng Clopper–Pearson; McNemar; tổng các bảng; 220/35 = 6,3; 341K/21K ≈ 16) — **tất cả khớp**.

---

## 1. Những gì đã thay đổi trong bản thảo (để nhóm rà soát)

| Mục | Thay đổi |
|---|---|
| Frontmatter | `\journal{Computer Networks}`; tiêu đề mới; abstract/keywords viết lại quanh *verification-guided synthesis*; khối Highlights để ở dạng comment |
| §1 Introduction | Thêm đoạn "central observation" dẫn tới ý tưởng tổng hợp chương trình; viết lại 4 contribution bullets, bullet 2 là verification-guided synthesis |
| §2 Related work | Thêm §2.3 *Program synthesis with verifier feedback* (CEGIS, HSA, Batfish, Mondal); nêu rõ 3 khác biệt với LLM+verifier cho cấu hình; Table 1 thêm cột *Verified response logic* và chú thích tiêu chí "Partial" |
| §3 Problem formulation | Thêm bảng ký hiệu (Table 2); đổi ký hiệu quyết định `d` → `u` (tránh trùng với đích `d`); định nghĩa Containment/Latency/λ trong Eq. (1); thêm §3.5 *Response synthesis problem* (Definition 1–3: feature abstraction, ngôn ngữ/chương trình, verifier); Proposition 2 chỉ còn claim I1, I2, I3, I4ˢ (TTL/scope), I5 — **không** claim phần rate-limit của I4 và authorization của I6 (reviewer sẽ bắt lỗi này); **Lemma 1** (ensemble theo đa số nghiêm ngặt vẫn verified) kèm chứng minh; **Proposition 3** (chi phí & kết thúc); đoạn về cái mà feature abstraction "mua" và "mất" |
| §4 Method | Đổi tên §4.3 thành *Verification-Guided Response Synthesis*; thêm **Algorithm 1** (vòng tổng hợp) và **Fig. 3** (sơ đồ vòng, TikZ); Algorithm 2 là thuật toán quyết định cũ; nêu rõ hành vi khi ứng viên bị loại / không có thành viên nào verified; bảng *program inputs* và bảng *decision schema* chuyển vào văn bản |
| §3.2 Threat model | Thừa nhận vector spoof địa chỉ *không* được bảo vệ (I2 bám header source) — chỉ là availability vector, bị chặn bởi I4 |
| §5 Experimental design | 6 RQ (thêm RQ3 sensitivity, S11 multi-source campaign); Table scenarios chuyển sang một cột; bổ sung metric cho vòng tổng hợp |
| §6 Results | Thêm: "What the verifier catches" + **Synthesis ablation** (gộp trong Table 5), ensemble size + cross-model (Table 6), CDF latency (Fig. 5), multi-source campaign (gộp trong Table 9), verifier scalability (đưa vào văn bản với |D(K)| tính sẵn); sweep: báo cáo CI trên 75 case riêng biệt (tránh pseudo-replication), McNemar p = 0,125 trên 75 case (so với 1,9e-6 nếu tính 375 quyết định); các bảng confusion-matrix, tau-sweep, inputs-map chuyển vào văn bản |
| §6.11 Discussion | Thêm hạn chế: spoofing, verifier chỉ kiểm chứng an toàn chứ không kiểm chứng "đúng ý"; đề xuất KB fault-injection |
| Bib | Thêm 4 entry: `solarlezama2006sketching`, `gulwani2017synthesis`, `kazemian2012hsa`, `fogel2015batfish` (vào `refs.bib`) |
| Hình | **`main.tex`: toàn bộ 5 hình là TikZ/pgfplots nội tuyến** (không còn `\includegraphics`): Fig. 1 kiến trúc (figure*, lane theo plane, hai đường compiled/runtime), Fig. 2 topology, Fig. 3 vòng tổng hợp, Fig. 4 Secure Framework (có nhánh reject fail-closed), Fig. 5 CDF latency (pgfplots, khung sẵn). Cần `\usepackage{tikz,pgfplots}` + thư viện `arrows.meta,positioning,fit,calc,backgrounds` (đã thêm vào preamble). **`main_oldfigs.tex`:** biến thể dùng lại 3 hình PDF gốc (`figs/overview_v2.pdf`, `figs/topology.pdf`, `figs/framework.pdf`) với caption đã cập nhật, giữ TikZ cho Fig. 3 và Fig. 5 — chọn một trong hai file |
| Bảng | Giảm từ 22 xuống **10 bảng**: (1) positioning, (2) notation, (3) policy matrix, (4) scenarios, (5) synthesis-loop dynamics + ablation, (6) sensitivity k + model, (7) agreement V0–V4 (gộp compiled + drift), (8) per-scenario outcomes + latency (table*), (9) adversarial safety + S11 campaign, (10) baselines: matrix sweep + S9 ablation |
| Khác | Thêm `\balance` trước bibliography |

---

## 2. Thực nghiệm bổ sung cần chạy (ứng với từng chỗ chữ đỏ)

Thứ tự ưu tiên theo mức độ quyết định đối với tiêu đề mới. Mỗi mục ghi: *ở đâu trong bản thảo* → *đo gì* → *cách làm*.

### E1 — Synthesis-loop dynamics (phần trên Table `tab:loop`, §6.1; số `n0`, `m`, `r` trong Abstract, §6.11, Conclusion) — **BẮT BUỘC**
- **Đo:** cho 6 lần tổng hợp đã có (5 thành viên ensemble + chương trình T=0): số counterexample ở vòng 0 (CE₀) phân theo check I3 / I4ˢ / I5 / C; số vòng repair đã dùng; **Acc₀** = độ đồng thuận của *ứng viên chưa verified ở vòng 0* trên 14.970 điểm graded; số DROP không an toàn (nguồn protected/external) mà ứng viên vòng 0 sẽ phát ra; self-review có được chấp nhận không và thay đổi bao nhiêu điểm; token mỗi vòng.
- **Cách làm:** artifact đã ghi `repair rounds` và token; cần dump thêm ứng viên trung gian mỗi vòng (nếu chưa lưu thì chạy lại 6 lần với cùng seed/temperature và log đầy đủ). Chấm Acc₀ bằng đúng grader của RQ1.
- **Điền:** `n0`/`m`/`r` ở Abstract; đoạn đỏ "Of the six initially synthesized programs…"; Table loop.

### E2 — Synthesis ablation (phần dưới Table `tab:loop`, §6.1) — **BẮT BUỘC** (bằng chứng trực tiếp cho "verification-guided")
- **Bốn nhánh:** (a) one-shot, không verifier; (b) repair only (≤3 vòng); (c) repair + self-review; (d) full ensemble k=5.
- **Lặp:** ≥20 lần tổng hợp độc lập mỗi nhánh tại T=0,7 trên KB gốc (V0); lặp lại trên V4.
- **Đo:** tỉ lệ ứng viên verified; Acc./Cov. trên 14.970 điểm graded (mean ± 95% CI); số DROP không an toàn; McNemar giữa các nhánh liên tiếp.
- **Điền:** đoạn đỏ "One-shot candidates verify in only…" và Table ablation.

### E3 — Mechanical-compiler control (1 câu đỏ ở §6.1) — nên làm
- Viết script sinh chương trình **chỉ từ các trường có cấu trúc** của catalog (documented response, severity, zone coverage), không dùng LLM. Chấm Acc./Cov. Kết quả cho biết LLM đóng góp đúng vào các entry "chỉ có trong prose" (V3).
- Đồng thời làm rõ cho reviewer: grader đọc trường nào của catalog, và vì sao Baseline-C-strongest không đọc được (mục §3.5 đã nêu lý do grader không thể là chương trình; cần một câu mô tả cụ thể cấu trúc trường "documented response" trong §5.4).

### E4 — Ensemble size (phần trên Table `tab:sensitivity`, §6.3)
- k ∈ {1, 3, 5, 7, 9}; lấy ensemble từ một pool ~30 chương trình tổng hợp tại T=0,7 (resample không hoàn lại), ≥10 ensemble mỗi k.
- **Đo:** Acc., Cov., số điểm abstain, token (tuyến tính theo k). Giải thích coverage V4 = 92,3 % theo k.
- *Tuỳ chọn:* T ∈ {0; 0,3; 0,7; 1,0} tại k=5.

### E5 — Cross-model synthesis (phần dưới Table `tab:sensitivity`, §6.3; câu đỏ §5.2; §6.11)
- Chọn 2 model open-weight khác (gợi ý: một dense ~70B và một MoE ~30B, khác nhà cung cấp) — đây là bằng chứng duy nhất cho R6.
- Cùng prompt, cùng η_max=3, k=5, T=0,7, cùng verifier.
- **Đo:** Pass@0 (tỉ lệ verified ở vòng 0), số vòng trung bình, số ứng viên bị loại, Acc./Cov. của ensemble, token. Khẳng định: không model nào được verifier cho qua một quyết định không an toàn.

### E6 — Latency: phân rã & CDF (Fig. `fig:latency_cdf`, đoạn đỏ §6.4, §6.10)
- Từ log 40 run live mỗi cấu hình: xuất 4 file CSV hai cột `t,F` (CDF thực nghiệm) vào `data/cdf_decide_bizm.csv`, `data/cdf_decide_runtime.csv`, `data/cdf_visible_bizm.csv`, `data/cdf_visible_runtime.csv`, rồi bỏ comment 4 dòng `\addplot ... table` trong Fig. 5 (pgfplots) và xoá node chữ đỏ + 4 mark median tạm. Nếu được, tăng N ≥ 100/run để có p99.
- **Phân rã** decision latency compiled path: program evaluation (2–17 ms) + validation + Secure Framework RTT. Giải thích vì sao S1/S3 ≈ 1,1–1,3 s còn S2/S4 ≈ 0,3 s (connection reuse? polling interval?); giải thích outlier Visible 7,59 s của Runtime-only S3.
- **Làm rõ 23,7 s** (median runtime path trong injected runs) so với 3,1 s live và timeout 15 s: có phải 2 model call (reasoning + audit trace) cộng queueing khi nhiều alert tới cùng lúc? Trích log để nêu per-stage breakdown.

### E7 — Throughput stress (đoạn đỏ §6.10)
- Replay alert của các signature được cover với offered load λ ∈ {10, 50, 100, 500, 1000} alert/s trong ≥120 s (bỏ dedup để đo decision plane).
- **Đo:** sustained rate μ, p50/p95/p99 decision time, queue depth theo thời gian, chi phí history lookup; Runtime-only: điểm bão hoà theo concurrency model-call c.

### E8 — Multi-source campaign S11 (phần dưới Table `tab:safety`, §6.5; Table scenarios; đoạn inputs trong §6.7)
- n_s ∈ {3, 5, 8, 12} nguồn không protected, phát policy violation trong 60 s; N ≥ 5 run mỗi n_s.
- Biến thể **decoy**: alert từ địa chỉ *giả mạo* không protected nhằm làm cạn giới hạn; sau đó một nguồn thật vi phạm → đo trễ containment t′.
- **Đo:** số nguồn contained trong phút đầu và tổng; thời gian đến khi tất cả bị contained; FP; thử nâng giới hạn 5/min → L′ và nêu trade-off.

### E9 — Verifier scalability (đoạn đỏ cuối §6.8; spec máy ở §5.1)
- Sinh KB tổng hợp với (|Z|, |Σ|) = (16, 60), (32, 120), (64, 250); |D(K)| = 987.224 / 7.379.064 / 59.386.600 (đã tính theo Proposition 3 và ghi trong văn bản; ước lượng tuyến tính từ 5 s: 36 s / 271 s / 36 phút).
- **Đo:** thời gian verify một chương trình trên 1 core và song song theo signature trên p core; RAM; thời gian compile và số token prompt (KB 22K token sẽ tăng — ghi nhận giới hạn context).
- Ghi CPU/core/RAM của máy chạy verifier vào §5.1.

### E10 — Thống kê resynthesis V1–V4 (câu đỏ §6.2)
- Số ứng viên bị verifier loại trên 4×k lần tổng hợp; tỉ lệ counterexample đến từ zone PAYMENTS và các signature permitted-path của V1.

### E11 — Xác nhận số liệu nhỏ
- Baseline-B: xác nhận n = 90 quyết định S7 (lower bound 96,0 % khớp 90/90). Đang để `\red{90}`.
- Table `tab:baselines`: xác nhận đơn vị *Edges closed / Legit. flows cut* (tổng trên 375 quyết định hay trên 75 case?). Đang để chú thích đỏ.

### E12 — (Tuỳ chọn, supplementary) KB fault injection
- Gieo lỗi vào catalog (đổi documented response, đổi zone của host) → tổng hợp → đo: chương trình sai đúng theo lỗi gieo nhưng vẫn verified (không bao giờ unsafe). Chứng minh câu "consistently wrong but never unsafe".

---

## 3. Việc còn lại trên bản thảo (không cần thực nghiệm)

1. **Hình:** cả 5 hình đã là TikZ nội tuyến và đã kiểm tra hiển thị (xem PDF kiểm tra). Khi biên dịch với elsarticle thật, kiểm tra lại Fig. 1 (`figure*`, dùng `\resizebox{\textwidth}`) và Fig. 2/3/4 (`\resizebox{\columnwidth}`) vì chiều rộng cột thật có thể khác lớp giả lập vài pt.
2. **Hình 5 (CDF):** đổ dữ liệu theo E6; khung pgfplots đã sẵn legend và mark median.
3. **Highlights:** Computer Networks yêu cầu 3–5 bullet ≤ 85 ký tự, nộp file riêng; đã để sẵn trong comment ở frontmatter. Nếu bản elsarticle của nhóm ≥ v3.3 có thể bỏ comment và dùng `\begin{highlights}` ngay trong file.
4. **Graphical abstract** (tuỳ chọn nhưng được khuyến khích): có thể dùng chính sơ đồ vòng tổng hợp.
5. **Data and Code Availability:** nêu tên repository (GitHub/Zenodo) thay vì "upon publication".
6. **Kiểm tra 4 bib entry mới** (năm, trang, DOI) — thông tin lấy từ bộ nhớ, cần đối chiếu DBLP/ACM DL: Solar-Lezama et al. ASPLOS 2006, pp. 404–415, doi 10.1145/1168857.1168907; Gulwani et al. FnT PL 4(1–2), 2017, doi 10.1561/2500000010; Kazemian et al. NSDI 2012, pp. 113–126; Fogel et al. NSDI 2015, pp. 469–483.
7. **Thuật ngữ:** tiêu đề dùng "Zero-Trust" (có gạch nối) còn thân bài dùng "Zero Trust" theo NIST. Chọn một cách (gợi ý: bỏ gạch nối trong tiêu đề cho nhất quán với NIST, hoặc đổi toàn bộ thân bài). Elsevier sẽ sắp chữ tiêu đề theo *sentence case* nên chỉ cần quyết định gạch nối.
8. **Acronym BIZM** (Bounded-Isolation Zero-Trust Microsegmentation) vẫn được giải nghĩa trong abstract; phù hợp vì "bounded" là ràng buộc mà synthesis phải thoả. Không cần đổi.
10. **Số trang:** bản shim ra 28 trang A4 hai cột; với elsarticle 5p ước lượng ~24–26 trang. Nếu cần rút thêm: rút §3.6 R1–R8 thành một đoạn; rút gọn §2.4–2.5.
11. **Macro `\red` / `\tbd`:** xoá khi đã điền hết số liệu (`grep -n "\\red\|\\tbd" main.tex` để kiểm tra).
12. **Dùng lại 3 hình gốc:** (a) đặt 3 file PDF vào `figs/`; (b) hình gốc vẫn ghi "Compiled Program (LLM-Compiled, Verified)" — nên đổi nhãn trong file nguồn thành "Synthesized program $\Pi^{\oplus}$ (verified)" cho khớp thuật ngữ mới (caption hiện đã chú thích tạm); (c) nếu phiên bản trước của bài **đã được xuất bản** ở nơi khác (ví dụ JNCA), cần xin phép/ghi nguồn theo chính sách Elsevier khi dùng lại hình; nếu chỉ là bản nộp/preprint thì không vướng gì; (d) Computer Networks yêu cầu hình vector hoặc ≥ 300 dpi, font nhúng — PDF gốc đáp ứng.
13. **BibTeX warning** (có từ trước): `mckeown2008openflow` dùng cả `volume` và `number` với kiểu `@inproceedings`; đổi sang `@article` (ACM SIGCOMM CCR 38(2)) để hết cảnh báo.
14. Cân nhắc câu trong §5.4 nêu rõ grader đọc trường nào của catalog (liên quan E3) để đóng "latent hole" mà reviewer-agent chỉ ra: "ground truth derived mechanically" vs "Baseline-C never reads the prose" vs V3 "prose only".

---

## 4. Ghi chú về kiểm tra thống kê (agent audit)

- Clopper–Pearson: 55/55 → [93,5; 100]; 0/22 → [0; 15,4]; 77/77 → [95,3; 100]; 89/89 → [95,9; 100]; 89/90 → [94,0; 100]; 0/50 → [0; 7,1]; 139/140 → [96,1; 100]; 0/27 → ≤ 12,8 %; 0/90 → ≤ 4,0 %; 12/12 → ≥ 73,5 %; 40/40 → ≥ 91,2 % — **tất cả đúng**.
- Sweep trên 75 case riêng biệt (đã sửa trong bảng): 33/75 → [32,5; 55,9]; 71/75 → [86,9; 98,5]; 75/75 → [95,2; 100]; McNemar 4 case bất đồng → p = 0,125.
- 7 tổ hợp history = 1 + 2×3 (prior=0 ép hai đếm còn lại = 0) — đã ghi vào Definition 1.
- V4: "seven errors" tại 99,97 % ⇒ số điểm được quyết định ≈ 23.000 (hợp lý với 37 signature, 10 zone) — không kiểm tra chính xác được từ văn bản; đã thêm cột *Graded* (chữ đỏ) vào Table `tab:agreement` để điền số điểm graded của V1–V4.