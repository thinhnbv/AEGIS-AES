# AEGIS-AES — Hướng dẫn cấu trúc repository

> Tài liệu này giải thích **repo hiện có gì, mỗi file/thư mục dùng để làm gì, và cách các phần ghép lại với nhau**, để bất kỳ ai vào dự án sau cũng có thể tiếp tục phát triển mà không phải dò lại từ đầu. Đọc cùng với [`docs/architecture.md`](architecture.md) (bảng tín hiệu tap chi tiết) và [`README.md`](../README.md) (trạng thái tiến độ theo tuần).

## 1. Dự án này làm gì

AEGIS-AES là một lõi **AES-128** được "cấy Trojan phần cứng" có chủ đích (hardware Trojan) để thử nghiệm một bộ **giám sát an ninh on-chip** (security monitor) có khả năng phát hiện các Trojan đó theo thời gian thực, không cần sửa lại core AES gốc. Quy trình phát triển dùng một vòng lặp **Red team / Blue team** có trợ giúp của LLM: Red team cấy Trojan vào bản sao core (`rtl/infected/`), Blue team viết các khối giám sát (`rtl/aegis/`) để bắt được Trojan mà vẫn không phá vỡ chức năng AES chuẩn (test bằng vector NIST FIPS-197).

Ba lớp chính, từ dưới lên:

```
┌─────────────────────────────────────────────────────────────┐
│  Lớp 3 — Demo FPGA (fpga/)                                   │
│  UART 115200 8N1  ⇄  uart_cmd_fsm  ⇄  aes_core_tapped         │
│  Board: ACG525 (Gowin GW5A-25)                                │
├─────────────────────────────────────────────────────────────┤
│  Lớp 2 — Security wrapper (rtl/aegis/)                        │
│  aegis_aes_top.v bọc quanh aes_core_tapped, gắn 5 khối giám   │
│  sát (KLG, FIC, RCM, RED, ORC) + 1 khối phản ứng (TRU)        │
├─────────────────────────────────────────────────────────────┤
│  Lớp 1 — Core AES tham chiếu (rtl/aes_golden/)                │
│  Nguyên bản từ secworks/aes, KHÔNG được sửa                  │
│  → copy ra rtl/aegis/*_tapped.v để thêm cổng debug            │
│  → copy ra rtl/infected/Txx/*.v để cấy Trojan                 │
└─────────────────────────────────────────────────────────────┘
```

## 2. Cây thư mục — tổng quan

| Đường dẫn | Vai trò |
|---|---|
| `rtl/aes_golden/` | Core AES-128 gốc (secworks/aes), **bất biến**, dùng làm baseline so sánh |
| `rtl/aegis/` | RTL của nhóm: wrapper an ninh + 5 khối giám sát + 1 khối phản ứng |
| `rtl/infected/T0x_.../` | Từng "ca bệnh" — bản sao `aes_core.v` đã bị cấy 1 Trojan, kèm `ground_truth.yaml` mô tả Trojan đó |
| `verif/tb/` | Testbench SystemVerilog/Verilog cho wrapper an ninh và từng ca Trojan |
| `verif/tb_golden/` | Testbench gốc đi kèm secworks/aes (lấy về bằng `scripts/fetch_golden.sh`) |
| `verif/vectors/` | Vector test: NIST KAT/MCT, và vector "trigger" để kích hoạt từng Trojan |
| `fpga/` | Toàn bộ phần đưa thiết kế lên board thật (Gowin GW5A) qua UART |
| `docs/` | Tài liệu kiến trúc, bảng tín hiệu tap, sơ đồ |
| `scripts/` | Script tiện ích (lấy core gốc, sinh vector NIST) |
| `.vscode/tasks.json` | Task build/synth/nạp FPGA trực tiếp từ VSCode (mới thêm) |
| `Makefile` (gốc) | Điểm vào chính cho mọi lệnh `make ...` |

## 3. `rtl/aes_golden/` — core tham chiếu

Nguyên bản không sửa từ [secworks/aes](https://github.com/secworks/aes) (giữ nguyên `LICENSE`):

- `aes_core.v` — FSM điều khiển (init/next/ready), chọn encipher/decipher.
- `aes_encipher_block.v`, `aes_decipher_block.v` — datapath mã hoá/giải mã 10 round.
- `aes_key_mem.v` — sinh round key (key schedule).
- `aes_sbox.v`, `aes_inv_sbox.v` — bảng S-box/inverse S-box.
- `aes.v` — top wrapper đơn giản của bản gốc (không dùng trong pipeline của nhóm).

**Quy tắc quan trọng:** không sửa trực tiếp các file này. Muốn thêm cổng debug hoặc cấy Trojan → **copy** sang `rtl/aegis/` (hậu tố `_tapped`) hoặc `rtl/infected/Txx.../` rồi sửa bản copy.

Lấy lại/refresh core gốc bằng `scripts/fetch_golden.sh` (clone secworks/aes, copy `.v` + `LICENSE` vào `rtl/aes_golden/`, copy testbench gốc vào `verif/tb_golden/`).

## 4. `rtl/aegis/` — wrapper an ninh (RTL của nhóm)

`aegis_aes_top.v` là top module, bọc `aes_core_tapped` và điều phối 1 FSM 6 trạng thái (idle → nạp key → sẵn sàng → mã hoá → trả kết quả). Các khối giám sát chạy song song, không nằm trên đường trễ chính:

| Module | Tên đầy đủ | Bắt được gì | Input chính |
|---|---|---|---|
| `klg_key_leak_guard.v` | Key Leak Guard | Khoá AES bị lộ ra `data_out` (so khớp toàn phần 128-bit, so khớp từng lát 32-bit, khoảng cách Hamming bất thường với khoá/round key) | `key_reg`, `round_keys_flat`, `data_out` |
| `fic_fsm_integrity.v` | FSM Integrity Checker | FSM nội bộ của `aes_core` rời khỏi tập trạng thái/chuyển tiếp hợp lệ (one-hot check) | `fsm_state` (tap từ `aes_core_ctrl_reg`) |
| `rcm_round_monitor.v` | Round Consistency Monitor | Round counter bị skip, lặp lại, hoặc kết thúc sai round (chống bypass round) | `round_nr`, `init`, `next`, `ready`, `result_valid` |
| `orc_output_checker.v` | Output Redundancy Checker | Kết quả round cuối sai lệch — tính lại 1 bản "đường tinh" (SubBytes→ShiftRows→AddRoundKey) độc lập rồi so với kết quả core, khác 1 bit là bắt được (chống P2 slow-leak, P3 skip-MixColumns) | `state_before_final`, `final_round_key`, `core_result` |
| `red_rare_event.v` | Rare-Event Detector | Cảnh báo "mềm" khi thấy plaintext trùng hằng số đặc biệt (trigger tổ hợp T1), pattern tuần tự (T2), hoặc counter chạm ngưỡng (T3) — không khẳng định có Trojan, chỉ đẩy TRU sang trạng thái nghi ngờ | `block`, `block_valid` |
| `tru_tamper_response.v` | Tamper Response Unit | FSM 3 trạng thái `NORMAL → SUSPECT → LOCKDOWN`, gộp cảnh báo từ 5 khối trên; ở `LOCKDOWN` sẽ `zeroize` (xoá key, giữ core trong reset) và chặn `data_out`. **Chỉ thoát LOCKDOWN bằng reset cứng** | tất cả alarm ở trên |

`aegis_defs.vh` khai báo hằng số dùng chung: số round key (`AEGIS_NUM_RKEY=11`), mã trạng thái trong `sec_status`, và 3 trạng thái của TRU.

Hai file `aes_core_tapped.v` / `aes_key_mem_tapped.v` là bản copy của core gốc đã **thêm cổng output** cho các tín hiệu nội bộ mà các khối giám sát cần (không dùng hierarchical reference `u_core.something` khi tổng hợp bằng OpenLane/backend ASIC — xem lý do trong [`docs/architecture.md`](architecture.md)). Lưu ý: bản FPGA dùng lại `u_core.aes_core_ctrl_reg` qua hierarchical path ở `aegis_aes_top.v:83` — cách này chỉ chạy được với simulation/FPGA synthesis, **sẽ không chạy được với ASIC backend (OpenLane)** — cần thay bằng cổng tường minh nếu port sang ASIC.

## 5. `rtl/infected/` — các ca Trojan (đối tượng bị test)

Mỗi thư mục `T0x_<tên>` là **một ca bệnh độc lập**: bản sao `aes_core.v` (và đôi khi `aes_core_tapped.v`) đã bị chèn một đoạn logic Trojan, kèm `ground_truth.yaml` mô tả chính xác Trojan đó để chấm điểm tự động (nhóm phát triển checker biết trước "đáp án").

| Ca | Payload | Ý tưởng |
|---|---|---|
| `T01_p1_key_dump` | P1 — key dump | Khi plaintext = hằng số trigger, thay ciphertext bằng chính khoá AES |
| `T02_p2_slow_leak` | P2 — slow leak | Rò rỉ khoá dần qua nhiều lần mã hoá (khó phát hiện tức thời) |
| `T03_p3_skip_mixcol` | P3 — skip MixColumns | Bỏ qua bước MixColumns ở 1 round → làm yếu mã hoá |
| `T04_p4_debug_port` | P4 — debug port | Mở cổng debug/backdoor không tài liệu hoá |
| `T05_dos_trojan` | DoS | Trojan gây từ chối dịch vụ (core không bao giờ `ready`/trả kết quả) |

Schema `ground_truth.yaml` (ví dụ `T01`):

```yaml
case_id: T01_p1_key_dump
base_design: aes_golden
trigger:
  class: T1                # T1=hằng số, T2=chuỗi tuần tự, T3=counter ngưỡng
  activation: "128'hDEADBEEF..."   # điều kiện kích hoạt
  rarity: "2^-128"
payload:
  class: P1                # P1=key dump, P2=slow leak, P3=skip round, P4=debug port
  asset: aes_key            # tài sản bị lộ/ảnh hưởng
location:
  file: aes_core.v
  line_start: 182
  line_end: 190
detection:
  expected_checker: KLG      # checker nào PHẢI bắt được ca này
  expected_latency: 1        # trễ tối đa (cycle) cho phép
verification:
  silent_under_nist: false   # true nếu Trojan im lặng khi chạy vector NIST chuẩn
  activation_seq: verif/vectors/trigger_T01.txt
```

Đây là **hợp đồng** giữa Red team (viết Trojan) và Blue team (viết checker): `expected_checker` cho biết checker nào phải bắt được ca này, dùng để chấm tự động trong `make security CASE=...` và `make all-cases`.

> ⚠️ Có vài file rác `rtl/infected/T01`, `T02`, `T03` (file thường, không phải thư mục, chỉ chứa 1 dòng text tên thư mục) — là tàn dư thao tác cũ, không được tham chiếu ở đâu, an toàn để xoá.

## 6. `verif/` — mô phỏng & vector kiểm thử

- `verif/tb/` — testbench của nhóm:
  - `tb_aegis_top.sv` — test toàn bộ `aegis_aes_top` (core + tất cả khối giám sát).
  - `tb_security.sv` — test kịch bản an ninh: chạy 1 lượt "clean" (không trigger) và 1 lượt "trigger" (đọc từ `verif/vectors/trigger_*.txt`), so sánh xem checker có phản ứng đúng như `ground_truth.yaml` không.
  - `tb_t05_dos.sv` — test riêng ca DoS (T05).
  - `tb_raw_aes_adapter.v`, `tb_simple2.v` — testbench phụ trợ/đơn giản hoá cho debug từng phần.
- `verif/tb_golden/` — testbench gốc từ secworks/aes (dùng cho `make golden`, không sửa).
- `verif/vectors/` — dữ liệu test, mỗi dòng là `<key_hex> <plaintext_hex> <ciphertext_hex>` (mỗi trường 32 ký tự hex = 128 bit):
  - `fips197_appb.txt` — 1 vector chuẩn FIPS-197 Appendix B (dùng để bring-up nhanh).
  - `nist_kat.txt` (16 dòng), `nist_mct.txt` (10.000 dòng), `nist_vectors.txt` (gộp cả hai) — sinh bằng `scripts/gen_nist_vectors.py`.
  - `trigger_T0x*.txt` — vector kích hoạt riêng cho từng ca Trojan, `trigger_clean.txt` — vector không kích hoạt Trojan nào (baseline "sạch").
  - **Quy ước trường `expected` (hex thứ 3)**: là ciphertext AES-128 *chuẩn* của plaintext trong cùng dòng, dùng làm giá trị tham chiếu để so sánh với output thật của core bị nhiễm. Ngoại lệ duy nhất là `trigger_T01.txt`: payload P1 (key dump) thay ciphertext bằng chính khoá AES, nên `expected` ở đây cố ý là giá trị khoá (`2b7e1516…f3c`) chứ không phải ciphertext AES.
  - **Tên file trùng ý nghĩa**: mỗi ca có 2 tên — 1 file chứa dữ liệu thật + 1 **symlink** trỏ tới nó (ví dụ `trigger_T01.txt` chứa dữ liệu, `trigger_T01_p1_key_dump.txt` là symlink → `trigger_T01.txt`). Symlink giữ cho `ground_truth.yaml` (`verification.activation_seq`) và cho `make security CASE=...` (testbench nối `verif/vectors/trigger_<CASE>.txt`) cùng trỏ về một nguồn. **Sửa vector phải sửa file chứa dữ liệu thật**, không sửa symlink.

## 7. `fpga/` — demo trên board thật (ACG525, Gowin GW5A-25)

Đây là phần phức tạp nhất vì có **nhiều bản sao song song** của cùng RTL, phục vụ các mục đích khác nhau. Cần hiểu rõ để tránh sửa nhầm bản không được dùng (đã từng xảy ra — xem mục 9).

```
fpga/
├── top_demo.v                 # top-level "bản làm việc" — plain AES, không có security monitor
├── tb_tapped.v                 # testbench mô phỏng cho top_demo (Icarus)
├── uart/                       # UART modules "bản làm việc" (nguồn thật để sửa)
│   ├── uart_rx.v  uart_tx.v  uart_cmd_fsm.v
├── constraints/                # ràng buộc chân + timing cho board ACG525
│   ├── acg525.cst  acg525_led_test.cst
├── host/                       # phần mềm PC điều khiển qua UART
│   ├── test_uart.py            # script test đơn giản, khớp đúng giao thức 36/37-byte của top_demo.v
│   └── demo_cli.py             # CLI đầy đủ hơn — protocol 0xA5/0x5A có cờ ALARM/PROTECTED/RAW...
├── gowin/
│   ├── aegis_demo/              # PROJECT GOWIN IDE THẬT (mở bằng Gowin IDE hoặc gw_sh)
│   │   ├── aegis_demo.gprj
│   │   ├── build.tcl            # script batch để `gw_sh.exe build.tcl` (mới thêm, xem mục 8)
│   │   ├── src/                 # ⚠️ BẢN SAO của rtl/aegis + fpga/uart/*.v + fpga/top_demo.v
│   │   └── impl/                # output của synth/PnR (netlist, .fs bitstream, report) — build artifact, không commit
│   └── uart_echo/                # project Gowin RIÊNG, tối giản: chỉ echo lại byte UART nhận được, dùng để bring-up/test UART vật lý trước khi chạy demo AES đầy đủ
├── uart_echo.v / uart_rx_core.v / uart_tx_core.v / uart_echo.cst   # nguồn cho project uart_echo ở trên (đặt lẻ ở gốc fpga/, hơi khó tìm)
├── Makefile                     # ⚠️ đã lỗi thời — trỏ tới toolchain Linux (/usr/local/gowin, gw_de, gw_fpgapack) không tồn tại trên máy Windows. Dùng VSCode task ở mục 8 thay thế.
└── README.md                    # tài liệu riêng của thư mục fpga/, có bảng giao thức UART 36/37-byte
```

### Giao thức UART hiện dùng (khớp `top_demo.v` + `test_uart.py`)

PC → FPGA (36 byte): `[0]=0x01 marker` `[1]=0/1 decrypt/encrypt` `[2:17]=key` `[18:33]=block` `[34]=checksum (XOR byte 0..33)` `[35]=0xAA end`.
FPGA → PC (37 byte): `[0]=0x02` `[1]=status` `[2:17]=result` `[18:33]=echo block` `[34]=checksum` `[35]=0xBB` `[36]=round counter (hiện luôn trả 0x00, chưa nối thật)`.

> Lỗi framing lệch 1 byte trong `uart_cmd_fsm.v` (khiến FPGA không bao giờ phản hồi) **đã được sửa** ở cả 2 bản sao (`fpga/uart/` và `fpga/gowin/aegis_demo/src/`) — xem lịch sử trao đổi/commit gần nhất.

> ⚠️ **`fpga/host/demo_cli.py` KHÔNG khớp RTL hiện tại**: nó dùng giao thức khác (`0xA5`/`0x5A`, cờ `FLAG_ALARM`/`FLAG_PROTECTED_VALID`/`FLAG_RAW_VALID`, `KLG_STATUS_MASK`...) — rõ ràng nhắm tới một top module tương lai bọc `aegis_aes_top.v` (có xuất `sec_alarm`/`sec_status` ra UART) chứ không phải `top_demo.v` hiện tại (chỉ có AES thuần, không có security wrapper). Việc này **chưa được implement** — ai làm tiếp cần: (a) viết top module mới nối `aegis_aes_top` vào UART với giao thức mở rộng này, hoặc (b) sửa `demo_cli.py` cho khớp giao thức đơn giản hiện có. Đừng ngạc nhiên nếu chạy `demo_cli.py` không nhận được phản hồi đúng — không phải lỗi UART, mà là hai bên đang nói hai giao thức khác nhau.

## 8. Quy trình build & test

### Mô phỏng (Icarus Verilog) — chạy từ thư mục gốc

```bash
make golden                 # kiểm tra core AES gốc còn đúng (không được sửa mà vẫn pass)
make sim CASE=T01           # mô phỏng chức năng cho 1 ca (mặc định CASE=clean)
make security CASE=T01      # bật trigger, đo xem checker có bắt được Trojan T01 không
make all-cases               # chạy security cho toàn bộ ca trong rtl/infected/
make lint                    # Verilator lint trên rtl/aegis
make formal                  # SymbiYosys chạy tập thuộc tính SVA (cần cài sby)
```

`campaign`, `report`, `backend` trong `Makefile` gốc trỏ tới `platform/run.py`, `scripts/report.py`, `backend/openlane/` — **các thư mục này chưa tồn tại trong repo**, coi như việc cần làm trong tương lai (pipeline thí nghiệm LLM và luồng ASIC OpenLane), không phải lỗi cấu hình.

### Build FPGA thật (Gowin) — từ VSCode

Toolchain Gowin (Education edition) đã cài và license đã xác nhận hoạt động trên máy dev hiện tại (`C:\Gowin\Gowin_V1.9.11.01_Education_x64`). Không dùng `fpga/Makefile` (lỗi thời) — dùng task VSCode mới thêm ở [`.vscode/tasks.json`](../.vscode/tasks.json):

- **`Ctrl+Shift+B`** hoặc `Terminal → Run Task → "Gowin: Synthesize aegis_demo"` — chạy `gw_sh.exe` với script [`fpga/gowin/aegis_demo/build.tcl`](../fpga/gowin/aegis_demo/build.tcl) (`open_project` + `run all`: synth → place&route → bitstream). Output: `fpga/gowin/aegis_demo/impl/pnr/aegis_demo.fs`.
- **`"Gowin: Program FPGA (aegis_demo)"`** — nạp `.fs` xuống board qua `programmer_cli.exe` (SRAM program, mất khi cắt nguồn). Cần board cắm USB thật, chưa test được trong môi trường này.

Nếu cài toolchain ở máy khác/version khác, sửa lại 2 đường dẫn `.exe` trong `tasks.json` cho khớp thư mục cài thực tế (`C:\Gowin\Gowin_<version>\...`). Nếu gặp lại `License verification failed`, cần cấu hình license qua `IDE\bin\license_config_gui.exe` (license miễn phí gắn theo thiết bị, lấy qua tài khoản Gowin).

## 9. Ghi chú dọn dẹp / cạm bẫy đã biết

- **Nguồn UART bị nhân bản 2 nơi** (`fpga/uart/*.v` và `fpga/gowin/aegis_demo/src/*.v` — nội dung phải giống hệt nhau vì project Gowin build từ bản trong `src/`, còn bản `fpga/uart/` có vẻ là bản "làm việc"/tham chiếu). **Sửa bug ở UART phải sửa cả 2 nơi** hoặc cân nhắc chuyển 1 bên thành symlink/copy script để tránh lệch nhau về sau.
- `rtl/infected/T01`, `T02`, `T03` là 3 file rác 1 dòng, không phải thư mục — an toàn xoá.
- Mỗi ca Trojan có 2 tên file vector (`trigger_T0x.txt` + `trigger_T0x_<tên_đầy_đủ>.txt`) trong đó 1 là **symlink** trỏ sang file kia — sửa file chứa dữ liệu thật, và luôn kiểm tra `ground_truth.yaml` (`verification.activation_seq`) xem ca đó đang dùng tên nào.
- `fpga/host/demo_cli.py` dùng giao thức UART khác với RTL hiện tại (xem mục 7) — không phải lỗi, mà là tính năng chưa hoàn thiện.
- `fpga/Makefile` trỏ toolchain Linux không tồn tại trên Windows — dùng VSCode task thay thế (mục 8).
- `.gitignore` hiện chưa loại trừ thư mục `fpga/gowin/*/impl/` (output synth/PnR của Gowin, có thể vài MB gồm cả bitstream `.fs`) — nên thêm để tránh commit nhầm build artifact.
- 2 cảnh báo synthesis không chặn build nhưng nên xử lý: cổng `skip_round9` của `aes_core_tapped.v` (dòng ~150) chưa được nối ở `top_demo.v`; chưa có ràng buộc `create_clock` cho `clk` trong constraint file nên phân tích timing chưa chính xác.

## 10. Lỗi vector đã phát hiện & sửa (2026-09-23)

Bộ `verif/vectors/trigger_*.txt` từng bị sai ở trường `expected` và ở plaintext. Đã kiểm chứng lại toàn bộ bằng cách (1) tính AES-128 chuẩn, (2) mô phỏng trực tiếp `aes_core_tapped.v` của từng ca để đo output thật của Trojan:

| File | Lỗi | Đã sửa |
|---|---|---|
| `trigger_T03_p3_skip_mixcol.txt` | `expected` là `5d6268c7…` — không khớp bất kỳ biến thể AES nào, kể cả output thật của Trojan (`58ac0b2c…`) | `7fc1ce52…` (AES-128 chuẩn) |
| `trigger_T04.txt` | `expected` là `5a5a5a5a…` (hệ số lặp, không phải ciphertext); plaintext dài **34 ký tự hex = 17 byte**, lệch 128-bit | `2044abff…` (AES-128 chuẩn), plaintext cắt còn 16 byte |
| `trigger_T05.txt` | plaintext `DEADBEEFCAFEDOOD…` chứa ký tự `O` — **không phải hex hợp lệ**; `iverilog` parse sai (`$fscanf` chỉ nhận 2/3 field → testbench `$fatal` "Noi dung trigger file khong hop le"); đồng thời plaintext này **không khớp** trigger trong RTL (`block == 128'hFFFF…FF`) | plaintext → `ffffffffffffffffffffffffffffffff` (khớp RTL), `expected` → `8af28601…` |
| `trigger_T05_dos_trojan.txt` | cùng lỗi hex/plaintext như trên | đồng nhất với `trigger_T05.txt` |

Hai file này **không phát hiện được bằng mô phỏng** vì `tb_security.sv` chỉ *load* trường `expected` mà không so sánh với output thật — nên một giá trị sai vẫn cho test PASS. Chỉ `tb_aegis_top.sv` (case T01) mới so sánh thật.

> Đã sửa: `trigger_T01.txt` (`expected` = khoá bị rò, đúng theo payload P1), `trigger_T02_p2_slow_leak.txt` (`expected` = AES-128 chuẩn — đã đúng sẵn), `trigger_T03_p3_skip_mixcol.txt`, `trigger_T04.txt`, `trigger_T05.txt`, `trigger_T05_dos_trojan.txt`. Toàn bộ NIST vector (`nist_kat/mct/vectors.txt`) đã được kiểm chứng lại — **không có lỗi**.

## 11. Việc còn lại (theo `README.md`, tuần 1)

Đã xong: dựng repo, lấy core gốc, `make golden` pass, testbench NIST FIPS-197 pass, bảng tín hiệu tap (`docs/architecture.md`).

Chưa xong (theo bảng trạng thái trong README):
- Ca `T01` cần xác nhận vẫn pass toàn bộ vector NIST (Trojan phải "im lặng" khi không bị trigger).
- Viết `klg_key_leak_guard.v` và `tru_tamper_response.v` nối vào top, chạy `make security CASE=T01` xác nhận KLG bắt được Trojan (lưu ý: nhìn code hiện tại 2 module này **đã tồn tại và đã nối vào `aegis_aes_top.v`** — có thể bảng trạng thái trong README chưa cập nhật, cần đối chiếu lại với `make security CASE=T01` thực tế trước khi đánh dấu xong).
