# Kiến trúc AEGIS-AES & Bảng tín hiệu Tap

## Bảng điểm tap tín hiệu nội bộ từ aes_core (Dựa trên secworks/aes)

| Tín hiệu cần tap | Nằm trong module | Dùng cho khối | Số dòng | Trạng thái lấy |
| :--- | :--- | :--- | :--- | :--- |
| `round_key [127:0]` | `aes_key_mem` | KLG | Cổng có sẵn | Có sẵn ở cổng - Dễ |
| `key [255:0]` | `aes_core` | KLG | Cổng có sẵn | Có sẵn ở top - Dễ |
| `ready`, `result_valid` | `aes_core` | RCM, ORC | Cổng có sẵn | Có sẵn ở top - Dễ |
| `result [127:0]` | `aes_core` | KLG, ORC | Cổng có sẵn | Có sẵn ở top - Dễ |
| `key_mem[0:14]` | `aes_key_mem` | KLG | Dòng 77 | **Khó - Cần thêm cổng** |
| `aes_core_ctrl_reg [1:0]` | `aes_core` | FIC | Dòng 73 | **Khó - Cần thêm cổng** |
| `muxed_round_nr [3:0]` | `aes_core` | RCM | Dòng 106 | **Khó - Cần thêm cổng** |

> **Lưu ý triển khai phần cứng (Dành cho Backend/FPGA):** 
> Các tín hiệu "Khó" không thể dùng tham chiếu phân cấp (`.`) khi tổng hợp logic bằng OpenLane. Nhóm thiết kế cần sao chép file `aes_core.v` và `aes_key_mem.v` thành `aes_core_tapped.v` và `aes_key_mem_tapped.v` (lưu ở `rtl/aegis/`), sau đó khai báo thêm các biến này thành cổng `output` để nối ra ngoài. Khối `aes_key_mem_tapped` cần flatten `key_mem[0:10]` thành cáp 1408-bit.
