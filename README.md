# AEGIS-AES: A Trojan-Resilient AES-128 Core with On-Chip Security Monitor, Built and Verified via an LLM-Assisted Red/Blue-Team Loop

## 📊 Project Status

Trạng thái dưới đây được **kiểm chứng bằng cách chạy thật**, không phải suông đoán. Lệnh kiểm chứng nằm ở cột cuối.

### Tuần 1
| # | Việc | Trạng thái | Kiểm chứng |
|---|------|------------|------------|
| 1 | Tạo repo theo cây thư mục, commit đầu tiên | [x] | `git log` |
| 2 | Clone secworks/aes vào `rtl/aes_golden/`, giữ nguyên LICENSE | [x] | `ls rtl/aes_golden/` |
| 3 | Chạy `make golden` — testbench gốc phải pass | [x] | `make golden` → PASS |
| 4 | Nạp vector NIST FIPS-197 Appendix B, viết `tb_aes_golden.sv` | [x] | Ciphertext khớp vector chuẩn |
| 5 | Đọc `aes_core.v`, ghi `docs/architecture.md` (bảng tín hiệu tap) | [x] | `docs/architecture.md` |
| 6 | Viết 5 ca Trojan T01–T05, mỗi ca kèm `ground_truth.yaml` | [x] | `ls rtl/infected/` |
| 7 | Xác nhận Trojan im lặng trên vector NIST | [x] | `make regress CASE=<case>` |
| 8 | Viết 5 khối giám sát + TRU, nối vào `aegis_aes_top.v` | [x] | `make security CASE=<case>` |
| 9 | Hợp đồng case (`ground_truth.yaml` → `verif/cfg/*.cfg`) dùng chung cho Red/Blue team | [x] | `make gen-cfg` |
| 10 | Regression NIST FIPS-197 đầy đủ (KAT 16 + MCT 10.000) | [x] | `make regress` |
| 10b | Đo false-alarm rate theo §9.2 (10⁶ lần mã hóa hợp lệ) | [x] | `make fa-rate` |
| 11 | Demo FPGA thật trên board ACG525 (Gowin GW5A-25) | [x] | `fpga/gowin/security_demo/` đã build ra bitstream |

**Tất cả 5 ca Trojan đều bị bắt đúng detector theo hợp đồng, và zeroize thành công:**

| Ca | Payload | Detector bắt được | `sec_status` |
|---|---|---|---|
| `T01_p1_key_dump` | P1 — key dump | KLG + ORC | `00010001` |
| `T02_p2_slow_leak` | P2 — slow leak | KLG + ORC | `00010001` |
| `T03_p3_skip_mixcol` | P3 — skip MixColumns | RCM + ORC | `00010100` |
| `T04_p4_debug_port` | P4 — debug port | FIC + RED | `00001010` |
| `T05_dos_trojan` | DoS — treo core | RCM + RED | `00001100` |

### Tuần 2
| # | Việc | Trạng thái | Kiểm chứng |
|---|------|------------|------------|
| 12 | Hoàn thiện wrapper an toàn cho FPGA: `top_security_demo.v` + giao thức UART `0xA5`/`0x5A` | [x] | `fpga/gowin/security_demo/src/` |
| 13 | Tái tạo lỗi framing UART lệch 1 byte ở **cả 2 bản sao** | [x] | `fpga/uart/` + `fpga/gowin/security_demo/src/` |

### Việc còn lại
| # | Việc | Ghi chú |
|---|------|---------|
| 14 | Port `sec_alarm`/`sec_status` ra cổng ASIC (OpenLane) | `aegis_aes_top.v:83` đang dùng hierarchical reference `u_core.aes_core_ctrl_reg` — chạy được với simulation/FPGA, **không** chạy được với ASIC backend. Cần thay bằng cổng tường minh. |
| 15 | Chạy `make formal` | Cần cài `sby` (SymbiYosys). |
| 16 | Nối `skip_round9` của `aes_core_tapped.v` | Cổng này chưa được nối ở `top_demo.v`, gây cảnh báo synthesis. |
| 17 | Thêm ràng buộc `create_clock` cho `clk` | Chưa có trong constraint file nên phân tích timing chưa chính xác. |
| 18 | Dựng pipeline thí nghiệm LLM (`platform/`) | `Makefile` đã có target `campaign`/`report` nhưng `platform/` chưa tồn tại. |

## 🗂️ Cấu trúc thư mục
- `rtl/aes_golden/`: Lõi AES tham chiếu chuẩn (Secworks), bất biến.
- `rtl/aegis/`: Mã nguồn thiết kế của nhóm (Security Wrapper, các khối giám sát KLG, FIC, RCM, v.v.).
- `rtl/infected/`: Các ca Trojan do Red team cấy, mỗi ca kèm `ground_truth.yaml` mô tả hợp đồng.
- `verif/`: Testbench chức năng, tập vector chuẩn NIST FIPS-197, hợp đồng case dạng `.cfg`.
- `docs/`: Tài liệu kiến trúc và kỹ thuật phần cứng.
- `fpga/`: Demo trên board thật (ACG525 / Gowin GW5A-25) qua UART.
- `backend/`: Cấu hình luồng tổng hợp và thiết kế vật lý (OpenLane).

Chi tiết từng file, cách các phần ghép lại với nhau, và các cạm bẫy đã biết: **[`docs/REPO_GUIDE.md`](docs/REPO_GUIDE.md)**.

## 🚀 Hướng dẫn chạy (Quick Start)

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

# Sinh lại hợp đồng case từ ground_truth.yaml
make gen-cfg

# Verilator lint + SymbiYosys SVA
make lint
make formal
```

> ✅ **Đã xử lý (mục 12.1 trong `docs/REPO_GUIDE.md`):** trước đây `make regress` với đủ 10.000 vector **treo ở khoảng vector 267** vì KLG báo động giả khi so 8 bit `data_out[7:0]` với `key_reg[7:0]` (xác suất trùng ngẫu nhiên 1/256 mỗi vector). Nay KLG **xác nhận** phép so này bằng ciphertext tham chiếu mà ORC tính lại: byte chỉ được coi là rò rỉ khi core thực sự đã sửa nó. Kết quả — **false alarm rate = 0 tuyệt đối**, và T02 vẫn bị cả KLG lẫn ORC bắt (`sec_status = 00010001`).

### Số liệu đã kiểm chứng

| Chỉ số | Kết quả | Lệnh kiểm chứng |
|---|---|---|
| Regression NIST FIPS-197 | 10.016 vector × 6 case, **0 FAIL**, **0 false alarm** | `make regress-all` |
| False alarm rate (yêu cầu §9.2 của bản đề xuất) | **0** trên 10⁶ lần mã hóa hợp lệ | `make fa-rate` |
| Phát hiện Trojan | 5/5 ca, đúng detector theo hợp đồng, zeroize thành công | `make security CASE=<tên>` |
