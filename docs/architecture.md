# Kiến trúc AEGIS-AES & Bảng tín hiệu Tap

## Bảng điểm tap tín hiệu nội bộ từ aes_core (Dựa trên secworks/aes)

| Tín hiệu cần tap | Nằm trong module | Dùng cho khối | Số dòng | Trạng thái lấy |
| :--- | :--- | :--- | :--- | :--- |
| `round_key [127:0]` | `aes_key_mem` | KLG | Cổng có sẵn | Có sẵn ở cổng - Dễ |
| `key [255:0]` | `aes_core` | KLG | Cổng có sẵn | Có sẵn ở top - Dễ |
| `ready`, `result_valid` | `aes_core` | RCM, ORC | Cổng có sẵn | Có sẵn ở top - Dễ |
| `result [127:0]` | `aes_core` | KLG, ORC | Cổng có sẵn | Có sẵn ở top - Dễ |
| `key_mem[0:14]` | `aes_key_mem` | KLG | Dòng 77 | ✅ Đã thêm cổng `round_keys_flat [1407:0]` |
| `aes_core_ctrl_reg [1:0]` | `aes_core` | FIC | Dòng 73 | ✅ Đã thêm cổng `fsm_state [1:0]` |
| `muxed_round_nr [3:0]` | `aes_core` | RCM | Dòng 106 | ✅ Đã thêm cổng `muxed_round_nr [3:0]` |

> **Lưu ý triển khai phần cứng (Dành cho Backend/FPGA):**
> Các tín hiệu "Khó" không thể dùng tham chiếu phân cấp (`.`) khi tổng hợp logic bằng OpenLane. Nhóm thiết kế cần sao chép file `aes_core.v` và `aes_key_mem.v` thành `aes_core_tapped.v` và `aes_key_mem_tapped.v` (lưu ở `rtl/aegis/`), sau đó khai báo thêm các biến này thành cổng `output` để nối ra ngoài. Khối `aes_key_mem_tapped` cần flatten `key_mem[0:10]` thành cáp 1408-bit.

> ✅ **Đã triển khai đầy đủ.** Cả 3 cổng tap đều đã là output tường minh trên `aes_core_tapped.v`:
> `round_keys_flat [1407:0]` (KLG), `fsm_state [1:0]` (FIC), `muxed_round_nr [3:0]` (RCM), `state_before_final [127:0]` (ORC).
> `aegis_aes_top.v` nối thẳng qua `.fsm_state(core_fsm_state)` — **không còn** tham chiếu phân cấp `u_core.aes_core_ctrl_reg`, nên design tổng hợp được với OpenLane (ASIC) và Vivado (FPGA).
>
> ⚠️ `aes_core_tapped.v` có **7 bản copy** (1 trong `rtl/aegis/`, 5 trong `rtl/infected/T0*/`, 1 trong `fpga/gowin/security_demo/src/`, 1 trong `fpga/gowin/aegis_demo/src/`). Thêm cổng tap mới phải sửa **cả 7** — Gowin build từ bản trong `fpga/gowin/*/src/`, không phải `rtl/aegis/`.
