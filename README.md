# AEGIS-AES: A Trojan-Resilient AES-128 Core with On-Chip Security Monitor, Built and Verified via an LLM-Assisted Red/Blue-Team Loop

## 📊 Project Status

### **Tuần 1:**
| # | Việc | Xong khi | Trạng thái |
|---|------|----------|------------|
| 1 | Tạo repo theo cây thư mục ở mục 2, commit đầu tiên | git log có một commit | [x] |
| 2 | Clone secworks/aes vào rtl/aes_golden/, giữ nguyên LICENSE | Thư mục có đủ file .v | [x] |
| 3 | Chạy make golden - testbench gốc phải pass | Terminal in kết quả pass |[x]|
| 4 | Nạp vector NIST FIPS-197 Appendix B, viết tb_aes_golden.sv của đội | Ciphertext khớp vector chuẩn |[x]|
| 5 | Đọc aes_core.v, ghi ra docs/architecture.md danh sách tín hiệu cần tap | Có bảng tên tín hiệu |[x]|
| 6 | Viết case T01 (P1 key dump), tạo ground_truth.yaml | make sim CASE=T01 chạy được |[]|
| 7 | Xác nhận T01 vẫn pass toàn bộ vector NIST (Trojan im lặng) | Không mismatch |[]| 
| 8 | Viết klb_key_leak_guard.v và tru_tramper_response.v, nối vào top | make security CASE=T01 báo KLG bắt được |[]|

## 🗂️ Cấu trúc thư mục
- `rtl/aes_golden/`: Lõi AES tham chiếu chuẩn (Secworks), bất biến.
- `rtl/aegis/`: Mã nguồn thiết kế của nhóm (Security Wrapper, các khối giám sát KLG, FIC, RCM, v.v.).
- `verif/`: Testbench chức năng, tập vector chuẩn NIST FIPS-197.
- `docs/`: Tài liệu kiến trúc và kỹ thuật phần cứng.
- `backend/`: Cấu hình luồng tổng hợp và thiết kế vật lý (OpenLane).

## 🚀 Hướng dẫn chạy (Quick Start)
Chạy kiểm chứng chức năng mô phỏng lõi gốc với Icarus Verilog:
```bash
make golden