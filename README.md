# AEGIS-AES: A Trojan-Resilient AES-128 Core with On-Chip Security Monitor, Built and Verified via an LLM-Assisted Red/Blue-Team Loop

Dự án cấy Trojan phần cứng vào lõi AES-128 (bản tham chiếu từ [secworks/aes](https://github.com/secworks/aes)) và xây một bộ **giám sát an ninh on-chip** phát hiện Trojan theo thời gian thực — không sửa core AES gốc. Quy trình phát triển dùng vòng lặp **Red/Blue team** có trợ giúp LLM: Red team cấy Trojan vào bản copy core, Blue team viết các khối giám sát để bắt được Trojan trong khi vẫn giữ đúng chức năng AES chuẩn (test bằng vector NIST FIPS-197).

## Kiến trúc

Ba lớp, từ dưới lên:

```
Lớp 3 — Demo FPGA (fpga/)            UART 115200 ⇄ uart_cmd_fsm ⇄ aes_core_tapped
Lớp 2 — Security wrapper (rtl/aegis/)  aegis_aes_top + KLG/FIC/RCM/RED/ORC + TRU
Lớp 1 — Core AES tham chiếu (rtl/aes_golden/)  secworks/aes, bất biến
```

- `aegis_aes_top` bọc `aes_core_tapped`, 5 khối giám sát chạy **song song, không nằm trên đường trễ chính**, 1 khối phản ứng (TRU: `NORMAL → SUSPECT → LOCKDOWN`, zeroize + chặn output).
- Mỗi ca Trojan (5 ca, `rtl/infected/`) kèm `ground_truth.yaml` — hợp đồng giữa Red team và Blue team, được biên dịch thành `verif/cfg/*.cfg` cho testbench đọc.

Kết quả đã kiểm chứng: **5/5 ca Trojan bị bắt đúng detector, zeroize thành công; regression NIST FIPS-197 (10.016 vector × 6 case) 0 FAIL, 0 false alarm; false-alarm rate = 0 trên 10⁶ lần mã hóa hợp lệ.** Chi tiết và số liệu: [`docs/REPO_GUIDE.md`](docs/REPO_GUIDE.md).

| Ca | Payload | Detector bắt được | `sec_status` |
|---|---|---|---|
| `T01_p1_key_dump` | P1 — key dump | KLG + ORC | `00010001` |
| `T02_p2_slow_leak` | P2 — slow leak | KLG + ORC | `00010001` |
| `T03_p3_skip_mixcol` | P3 — skip MixColumns | RCM + ORC | `00010100` |
| `T04_p4_debug_port` | P4 — debug port | FIC + RED | `00001010` |
| `T05_dos_trojan` | DoS — treo core | RCM + RED | `00001100` |

## Cấu trúc thư mục

- `rtl/aes_golden/`: Lõi AES tham chiếu chuẩn (Secworks), bất biến.
- `rtl/aegis/`: Mã nguồn thiết kế của nhóm (Security Wrapper, các khối giám sát KLG, FIC, RCM, RED, ORC, TRU).
- `rtl/infected/`: Các ca Trojan do Red team cấy, mỗi ca kèm `ground_truth.yaml`.
- `verif/`: Testbench chức năng, tập vector chuẩn NIST FIPS-197, hợp đồng case dạng `.cfg`.
- `docs/`: Tài liệu kiến trúc và kỹ thuật phần cứng.
- `fpga/`: Demo trên board thật (ACG525 / Gowin GW5A-25) qua UART.
- `backend/`: Cấu hình luồng tổng hợp và thiết kế vật lý (OpenLane).

Chi tiết từng file, cách các phần ghép lại với nhau, và các cạm bẫy đã biết: **[`docs/REPO_GUIDE.md`](docs/REPO_GUIDE.md)**.

## Hướng dẫn chạy (Quick Start)

Tất cả lệnh chạy **từ thư mục gốc repo**.

```bash
# Kiểm tra core AES gốc còn nguyên vẹn
make golden

# Regression NIST FIPS-197: KAT 16 vector + MCT 10.000 vector
# (mặc định chạy đủ 10.000 vector, ~10 phút)
make regress CASE=clean

# Smoke test nhanh: chỉ 100 vector MCT (~6 giây)
make regress CASE=clean MCT_LIMIT=100

# Kiểm tra 1 ca Trojan: bật trigger, đo detector có bắt được không
make security CASE=T01_p1_key_dump

# Chạy security cho toàn bộ 5 ca
make all-cases

# Regression NIST cho tất cả ca (clean + 5 Trojan)
make regress-all

# Đo false-alarm rate trên lưu lượng mã hoá hợp lệ (yêu cầu §9.2)
make fa-rate
# Icarus mất hàng giờ cho 10^6; dùng Verilator (compiled C++) chạy trong giây:
make fa-rate SIM=verilator FA_KEYS=200 FA_PER_KEY=5000

# Sinh lại hợp đồng case từ ground_truth.yaml
make gen-cfg

# Verilator lint + SymbiYosys SVA
make lint
make formal
```
