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
| `verif/cfg/` | Hợp đồng case dạng phẳng, **sinh tự động** từ `ground_truth.yaml` bằng `scripts/gen_case_cfg.py` |
| `fpga/` | Toàn bộ phần đưa thiết kế lên board thật (Gowin GW5A) qua UART |
| `docs/` | Tài liệu kiến trúc, bảng tín hiệu tap, sơ đồ |
| `scripts/` | Script tiện ích (lấy core gốc, sinh vector NIST, sinh hợp đồng case) |
| `.vscode/tasks.json` | Task build/synth/nạp FPGA trực tiếp từ VSCode |
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
| `klg_key_leak_guard.v` | Key Leak Guard | Khoá AES bị lộ ra `data_out` (so khớp toàn phần 128-bit, so khớp từng lát 32-bit, khoảng cách Hamming bất thường với khoá/round key, và **so lát 8-bit có xác nhận bằng ciphertext tham chiếu của ORC**) | `key_reg`, `round_keys_flat`, `data_out`, `orc_ref_valid`, `orc_ref_result` |
| `fic_fsm_integrity.v` | FSM Integrity Checker | FSM nội bộ của `aes_core` rời khỏi tập trạng thái/chuyển tiếp hợp lệ (one-hot check) | `fsm_state` (tap từ `aes_core_ctrl_reg`) |
| `rcm_round_monitor.v` | Round Consistency Monitor | Round counter bị skip, lặp lại, hoặc kết thúc sai round (chống bypass round) | `round_nr`, `init`, `next`, `ready`, `result_valid` |
| `orc_output_checker.v` | Output Redundancy Checker | Kết quả round cuối sai lệch — tính lại 1 bản "đường tinh" (SubBytes→ShiftRows→AddRoundKey) độc lập rồi so với kết quả core, khác 1 bit là bắt được (chống P2 slow-leak, P3 skip-MixColumns). Đồng thời **export giá trị tính lại** (`orc_ref_result`) cho KLG dùng để xác nhận lớp dò rò rỉ 8-bit | `state_before_final`, `final_round_key`, `core_result` |
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

### 5.1 Hợp đồng case ở dạng phẳng (`verif/cfg/*.cfg`)

`ground_truth.yaml` là nguồn sự thật, nhưng testbench không đọc YAML được. `scripts/gen_case_cfg.py` biên dịch nó thành file `.cfg` phẳng trong `verif/cfg/`:

```bash
make gen-cfg     # sinh lại verif/cfg/*.cfg từ rtl/infected/*/ground_truth.yaml
```

File `.cfg` sinh ra có dạng:

```ini
[case]
case_id = T01_p1_key_dump
expected_mask = 01              # bitmask detector bắt buộc (KLG=FIC=RCM=RED=ORC)
expected_mask_bits = KLG
expected_latency = 1
expected_latency_cycles = 1     # -1 nếu hợp đồng không ràng buộc cycle
silent_under_nist = false       # true => Trojan phải im lặng hoàn toàn trên NIST
trigger_seq = verif/vectors/trigger_T01.txt
```

`verif/tb/aegis_cfg_reader.vh` là task đọc file này lúc chạy, dùng chung bởi `tb_security.sv` và `tb_regress_nist.sv`. Nhờ đó **Red team và Blue team không thể lặng lẽ hiểu sai nhau** — cả hai cùng tham chiếu một nguồn.

Mỗi ca có 2 file `.cfg`: `T01.cfg` (tên ngắn) và `T01_p1_key_dump.cfg` (tên đầy đủ) — giống cấu trúc symlink của `verif/vectors/trigger_*.txt`. `make gen-cfg` sinh cả hai.

> ✅ Các file rác `rtl/infected/T01`, `T02`, `T03` (file thường, không phải thư mục) **đã được xoá**.

## 6. `verif/` — mô phỏng & vector kiểm thử

- `verif/tb/` — testbench của nhóm:
  - `tb_aegis_top.sv` — test toàn bộ `aegis_aes_top` (core + tất cả khối giám sát).
  - `tb_security.sv` — test kịch bản an ninh: chạy 1 lượt "clean" (không trigger) và 1 lượt "trigger" (đọc từ `verif/vectors/trigger_*.txt`), so sánh xem checker có phản ứng đúng như `ground_truth.yaml` không.
  - `tb_regress_nist.sv` — **regression NIST FIPS-197** (KAT 16 + MCT 10.000 vector). Kiểm tra 2 tính chất cho mỗi vector: (1) ciphertext đúng chuẩn, (2) không monitor báo động giả trên traffic sạch.
  - `tb_t05_dos.sv` — test riêng ca DoS (T05).
  - `tb_raw_aes_adapter.v`, `tb_simple2.v` — testbench phụ trợ/đơn giản hoá cho debug từng phần.
  - `aegis_cfg_reader.vh` — task đọc hợp đồng case `verif/cfg/*.cfg` lúc chạy (dùng chung `tb_security.sv` + `tb_regress_nist.sv`).
- `verif/tb_golden/` — testbench gốc từ secworks/aes (dùng cho `make golden`, không sửa).
- `verif/cfg/` — hợp đồng case dạng phẳng, sinh tự động từ `ground_truth.yaml` (xem mục 5.1). **Không sửa tay** — chạy `make gen-cfg`.
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
│   ├── test_uart.py            # script test đơn giản, khớp giao thức 36/37-byte của top_demo.v
│   └── demo_cli.py             # CLI đầy đủ hơn — protocol 0xA5/0x5A có cờ ALARM/PROTECTED/RAW...
├── gowin/
│   ├── security_demo/           # ⭐ PROJECT CHÍNH — có aegis_aes_top + giao thức 0xA5/0x5A
│   │   ├── security_demo.gprj
│   │   ├── build.tcl            # script batch cho `gw_sh.exe build.tcl`
│   │   ├── src/                 # ⚠️ BẢN SAO của rtl/aegis + fpga/uart/*.v + top_security_demo.v
│   │   └── impl/                # output synth/PnR (netlist, .fs bitstream, report) — build artifact, không commit
│   ├── aegis_demo/              # project CŨ — plain AES, KHÔNG có security monitor
│   │   ├── aegis_demo.gprj
│   │   └── src/                 # top_demo.v, uart_cmd_fsm.v (giao thức 36/37-byte)
│   └── uart_echo/                # project RIÊNG, tối giản: chỉ echo byte UART nhận được, dùng để bring-up/test UART vật lý trước khi chạy demo AES đầy đủ
├── uart_echo.v / uart_rx_core.v / uart_tx_core.v / uart_echo.cst   # nguồn cho project uart_echo ở trên (đặt lẻ ở gốc fpga/, hơi khó tìm)
├── Makefile                     # ⚠️ đã lỗi thời — trỏ tới toolchain Linux (/usr/local/gowin, gw_de, gw_fpgapack) không tồn tại trên máy Windows. Dùng VSCode task ở mục 8 thay thế.
└── README.md                    # tài liệu riêng của thư mục fpga/, có bảng giao thức UART 36/37-byte
```

### Hai giao thức UART — đừng nhầm

Repo có **hai top module** với **hai giao thức khác nhau**. Chọn đúng cặp đi:

| | `top_demo.v` (bản cũ) | `top_security_demo.v` (⭐ bản chính) |
|---|---|---|
| Có security monitor? | ❌ AES thuần | ✅ `aegis_aes_top` (KLG/FIC/RCM/RED/ORC + TRU) |
| Preamble | `0x01` / `0x02` | `0xA5` / `0x5A` |
| Script PC tương ứng | `test_uart.py` | `demo_cli.py` |
| Project Gowin | `aegis_demo/` | `security_demo/` |
| Kết quả | chỉ ra ciphertext | ra ciphertext **+ cờ `ALARM`/`PROTECTED`/`RAW` + `sec_status`** |

**Giao thức của `top_demo.v`** (36/37 byte):

PC → FPGA (36 byte): `[0]=0x01 marker` `[1]=0/1 decrypt/encrypt` `[2:17]=key` `[18:33]=block` `[34]=checksum (XOR byte 0..33)` `[35]=0xAA end`.
FPGA → PC (37 byte): `[0]=0x02` `[1]=status` `[2:17]=result` `[18:33]=echo block` `[34]=checksum` `[35]=0xBB` `[36]=round counter (hiện luôn trả 0x00, chưa nối thật)`.

**Giao thức của `top_security_demo.v`** (0xA5/0x5A) — đã implement trong `uart_cmd_fsm_security.v`, khớp `demo_cli.py`:

PC → FPGA: `[0]=0xA5` `[1]=mode` `[2:17]=key` `[18:33]=block` `[34]=checksum` `[35]=0xAA`.
FPGA → PC: `[0]=0x5A` `[1]=flags` `[2:17]=result` `[18:33]=echo block` `[34]=checksum` `[35]=0xBB` `[36]=sec_status`.

Cờ trong byte `[1]` của response: `FLAG_RAW_VALID=1`, `FLAG_PROTECTED_VALID=2`, `FLAG_ALARM=4`, `FLAG_PROTECTED_BLOCKED=8`.

> ✅ `fpga/host/demo_cli.py` **đã khớp** RTL — nó nhắm vào `top_security_demo.v` + `uart_cmd_fsm_security.v`, cả hai đều đã tồn tại và đã build được bitstream `.fs`. (Trước đây tài liệu ghi "chưa được implement" — đã lỗi thời.)
>
> ⚠️ Nhưng `demo_cli.py` **không** nói chuyện được với `top_demo.v`. Chạy nhầm cặp sẽ không có phản hồi — đó là hai bên nói hai giao thức khác nhau, không phải lỗi UART.

## 8. Quy trình build & test

### Mô phỏng (Icarus Verilog) — chạy từ thư mục gốc

```bash
make golden                 # kiểm tra core AES gốc còn đúng (không được sửa mà vẫn pass)
make sim CASE=T01           # mô phỏng chức năng cho 1 ca (mặc định CASE=clean)
make security CASE=T01      # bật trigger, đo xem checker có bắt được Trojan T01 không
make all-cases              # chạy security cho toàn bộ ca trong rtl/infected/
make gen-cfg                # sinh lại verif/cfg/*.cfg từ ground_truth.yaml
make regress CASE=clean     # regression NIST FIPS-197 (KAT 16 + MCT 10.000)
make regress CASE=T01       # regression NIST cho 1 ca Trojan
make regress-all            # regression NIST cho clean + toàn bộ ca
make lint                   # Verilator lint trên rtl/aegis
make formal                 # SymbiYosys chạy tập thuộc tính SVA (cần cài sby)
```

### `make regress` — regression NIST FIPS-197

Chạy 2 tính chất cho **mỗi vector**:

1. **Chức năng đúng** — ciphertext phải khớp chính xác chuẩn NIST.
2. **Im lặng an ninh** — không monitor nào được báo động trên traffic sạch. Báo động ở đây là **false positive**.

`MCT_LIMIT` điều chỉnh số vector MCT (mặc định `0` = chạy hết 10.000):

```bash
make regress CASE=clean MCT_LIMIT=100   # smoke test ~6 giây
make regress CASE=clean                  # đầy đủ ~10 phút
```

> ⚠️ **Xem mục 12 — `make regress` với `MCT_LIMIT=0` hiện treo ở khoảng vector 267.** Dùng `MCT_LIMIT=100` cho smoke test cho tới khi được sửa.

`campaign`, `report`, `backend` trong `Makefile` gốc trỏ tới `platform/run.py`, `scripts/report.py`, `backend/openlane/` — **các thư mục này chưa tồn tại trong repo**, coi như việc cần làm trong tương lai (pipeline thí nghiệm LLM và luồng ASIC OpenLane), không phải lỗi cấu hình.

### Build FPGA thật (Gowin) — từ VSCode

Toolchain Gowin (Education edition) đã cài và license đã xác nhận hoạt động trên máy dev hiện tại (`C:\Gowin\Gowin_V1.9.11.01_Education_x64`). Không dùng `fpga/Makefile` (lỗi thời) — dùng task VSCode ở [`.vscode/tasks.json`](../.vscode/tasks.json):

- **`Ctrl+Shift+B`** hoặc `Terminal → Run Task → "Gowin: Synthesize security_demo"` — chạy `gw_sh.exe` với script [`fpga/gowin/security_demo/build.tcl`](../fpga/gowin/security_demo/build.tcl) (`open_project` + `run all`: synth → place&route → bitstream). Output: `fpga/gowin/security_demo/impl/pnr/security_demo.fs`.
- **`"Gowin: Program FPGA (security_demo)"`** — nạp `.fs` xuống board qua `programmer_cli.exe` (SRAM program, mất khi cắt nguồn). Cần board cắm USB thật, chưa test được trong môi trường này.

> ✅ Project `security_demo` đã build thành công — bitstream `.fs` có sẵn tại `fpga/gowin/security_demo/impl/pnr/security_demo.fs`.
>
> ⚠️ Task VSCode trước đây trỏ tới `fpga/gowin/aegis_demo/build.tcl` — **file này không tồn tại**, nên task luôn fail. Đã sửa sang `security_demo` (project có security monitor, khớp `demo_cli.py`).

Nếu cài toolchain ở máy khác/version khác, sửa lại 2 đường dẫn `.exe` trong `tasks.json` cho khớp thư mục cài thực tế (`C:\Gowin\Gowin_<version>\...`). Nếu gặp lại `License verification failed`, cần cấu hình license qua `IDE\bin\license_config_gui.exe` (license miễn phí gắn theo thiết bị, lấy qua tài khoản Gowin).

## 9. Ghi chú dọn dẹp / cạm bẫy đã biết

- **Nguồn UART bị nhân bản nhiều nơi.** Với demo có security monitor, cặp file phải khớp là `fpga/uart/uart_rx.v` + `fpga/uart/uart_tx.v` ↔ `fpga/gowin/security_demo/src/uart_rx.v` + `.../uart_tx.v`. **Sửa bug ở UART phải sửa cả 2 nơi.**
  - ⚠️ Nhưng `uart_cmd_fsm` **KHÔNG** cùng loại: `fpga/uart/uart_cmd_fsm.v` (giao thức 36/37 byte, cho `top_demo.v`) và `fpga/gowin/security_demo/src/uart_cmd_fsm_security.v` (giao thức 0xA5/0x5A, cho `top_security_demo.v`) là **hai module khác nhau, cố ý khác nhau**. Đừng "đồng bộ" chúng với nhau.
  - Ngoài ra `rtl/aegis/*.v` cũng bị copy vào `fpga/gowin/security_demo/src/`. Sửa RTL ở `rtl/aegis/` thì phải copy sang đó (hoặc tốt hơn: dùng script copy để tránh lệch).
- ✅ File rác `rtl/infected/T01`, `T02`, `T03` **đã được xoá**.
- Mỗi ca Trojan có 2 tên file vector (`trigger_T0x.txt` + `trigger_T0x_<tên_đầy_đủ>.txt`) trong đó 1 là **symlink** trỏ sang file kia — sửa file chứa dữ liệu thật, và luôn kiểm tra `ground_truth.yaml` (`verification.activation_seq`) xem ca đó đang dùng tên nào. Tương tự, `verif/cfg/` có cả `T0x.cfg` và `T0x_<tên_đầy_đủ>.cfg`.
- ✅ `fpga/host/demo_cli.py` **đã khớp** RTL (`uart_cmd_fsm_security.v`). Cặp dùng với nhau là `demo_cli.py` ↔ `top_security_demo.v`. Xem bảng so sánh 2 giao thức ở mục 7.
- `fpga/Makefile` trỏ toolchain Linux không tồn tại trên Windows — dùng VSCode task thay thế (mục 8).
- ✅ `.gitignore` **đã** loại trừ `fpga/gowin/*/impl/`, `*.fs`, `*.bin`, `*.db` và `*.gprj.user`.
- ⚠️ Chưa có ràng buộc `create_clock` cho `clk` trong constraint file nên phân tích timing chưa chính xác. (Cảnh báo synthesis cũ về cổng `skip_round9` chưa được nối ở `top_demo.v` **đã không còn đúng** — `skip_round9` chỉ còn trong bản copy `fpga/gowin/*/src/aes_encipher_block.v` dùng cho demo T03, không còn trong `rtl/aegis/aes_core_tapped.v`.)
- `rtl/infected/T0x_*/aes_core.v` là **bản sao core gốc, không phải bản bị nhiễm** — Trojan nằm trong `aes_core_tapped.v` cùng thư mục. `Makefile` đã `filter-out` file này khi biên dịch. Có thể xoá cho gọn, nhưng giữ lại cũng vô hại.
- File build artifact sót ở gốc repo (`a.out`) đã được `.gitignore` loại trừ bằng rule `*.out` — nhưng vẫn nên xoá khỏi đĩa cho gọn.

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

## 11. Việc còn lại

Đã xong và **đã kiểm chứng bằng cách chạy thật**:

- Dựng repo, lấy core gốc, `make golden` pass, testbench NIST FIPS-197 pass, bảng tín hiệu tap (`docs/architecture.md`).
- 5 ca Trojan T01–T05, mỗi ca kèm `ground_truth.yaml`. `make security CASE=<tên>` **pass cho cả 5**: detector bắt đúng theo hợp đồng, TRU vào LOCKDOWN, zeroize xoá `key_reg` + 11 round key, output bị chặn.
- Hợp đồng case dạng phẳng (`verif/cfg/*.cfg`) sinh tự động từ `ground_truth.yaml`.
- Regression NIST FIPS-197 (`tb_regress_nist.sv` + `make regress` / `make regress-all`): **10.016 vector × 6 case, 0 FAIL, 0 false alarm**.
- Đo false-alarm rate theo §9.2 (`make fa-rate`): **0 false alarm** trên 10⁶ lần mã hóa hợp lệ.
- Sửa false alarm `hit_byte_leak` bằng cách KLG xác nhận với ciphertext tham chiếu của ORC (mục 12.1).
- Demo FPGA `security_demo` build được bitstream `.fs`.

Còn lại:

| # | Việc | Ghi chú |
|---|------|---------|
| 1 | Port `sec_alarm`/`sec_status` ra cổng ASIC | `aegis_aes_top.v` dùng hierarchical reference `u_core.aes_core_ctrl_reg` — chạy được với simulation/FPGA, **không** chạy được với OpenLane backend. Cần cổng tường minh. |
| 2 | Chạy `make formal` | Cần cài `sby` (SymbiYosys) và tạo `verif/sva/aegis.sby` — thư mục này chưa tồn tại. |
| 3 | Nối `skip_round9` trong bản copy T03 | Cổng này chưa được nối ở `fpga/gowin/security_demo/src/aes_encipher_block.v` (bản copy cho demo T03) — `skip_round9` không còn trong `rtl/aegis/aes_core_tapped.v` nên không phải lỗi của bản chính, chỉ là bản copy FPGA thừa cổng, gây cảnh báo synthesis. |
| 4 | Thêm ràng buộc `create_clock` cho `clk` | Chưa có trong constraint file → phân tích timing chưa chính xác. |
| 5 | Đo LUT/FF/Fmax cho hai cấu hình | §7.3 yêu cầu số liệu cho bản "tiết kiệm" (≤15%) và "đầy đủ" (≤25%). |
| 6 | Dựng pipeline thí nghiệm LLM (`platform/`) | `Makefile` có target `campaign`/`report` nhưng `platform/` chưa tồn tại. |

---

## 12. Đã xử lý: KLG báo động giả trên `hit_byte_leak`

**Triệu chứng (đã xử lý).** `make regress CASE=<bất kỳ>` với `MCT_LIMIT=0` (đủ 10.000 vector) **treo ở khoảng vector 267** với mọi case — kể cả core sạch. Testbench dừng ở `wait (busy == 1'b0)` sau khi nạp key.

**Nguyên nhân gốc.** Trong [`rtl/aegis/klg_key_leak_guard.v`](../rtl/aegis/klg_key_leak_guard.v):

```verilog
wire hit_byte_leak =
    EN_BYTE_LEAK &&
    (data_out[BYTE_LEAK_INDEX*8 +: 8] == key_reg[BYTE_LEAK_INDEX*8 +: 8]);
```

Lớp dò này dành riêng cho payload **P2 của T02** (`result[7:0] = key[7:0]`), nhưng `EN_BYTE_LEAK` mặc định là `1` nên **bật cho mọi case, kể cả core sạch**. Với 8 bit, xác suất trùng ngẫu nhiên là **1/256 mỗi vector** → trong 10.000 vector, false alarm gần như chắc chắn (~39 lần kỳ vọng).

**Ví dụ cụ thể** (vector 266 của `nist_mct.txt`):

```
key    = 8dff6ab8c177ef0e248f03ad164f0350   → key[7:0]    = 0x50
output = 945e8cdeb465c52d78ab3d044b7cff50   → data_out[7:0] = 0x50
```

→ `hit_byte_leak` = 1 → `klg_alarm` = 1 → TRU vào LOCKDOWN + zeroize → wrapper kẹt ở `ST_IDLE` với `busy` = 1 vĩnh viễn → testbench treo.

**Vì sao các lần chạy `MCT_LIMIT=30` vẫn pass:** 30 vector đầu chưa tới vector 266, nên false alarm chưa kịp xảy ra. Đây là lý do mọi thống kê "PASS / 0 alarm" trước đây chỉ có giá trị cho **30 vector đầu**, không phải cho bộ 10.000.

---

## 12.1. Cách đã sửa: KLG xác nhận bằng ciphertext tham chiếu của ORC

Bài toán gốc: một phép so 8-bit **đơn lẻ** không thể vừa bắt được T02 vừa có false-alarm rate thấp, vì "byte rò rỉ" và "byte trùng ngẫu nhiên" có **cùng phân phối** trong một mẫu đơn lẻ. Cần thêm thông tin.

Thông tin đó **đã có sẵn trong thiết kế**: ORC tính lại ciphertext cuối cùng (SubBytes→ShiftRows→AddRoundKey) và so với kết quả core. Bản tính lại cho biết **byte nào thực sự bị sửa**.

KLG dùng giá trị này để **xác nhận** phép so byte:

| Tình huống | `ct[7:0]` | `orc_ref[7:0]` | `key[7:0]` | Kết luận |
|---|---|---|---|---|
| Trùng ngẫu nhiên | = key | = ct | = ct | **không rò rỉ** (core đúng) |
| T02 rò rỉ | = key | ≠ ct | = ct | **rò rỉ thật** |

Điều kiện báo động mới:

```verilog
wire byte_leak_corrob =
    EN_BYTE_LEAK &&
    orc_ref_valid &&
    (data_out[BYTE_LEAK_INDEX*8 +: 8] !=
     orc_ref_result[BYTE_LEAK_INDEX*8 +: 8]) &&
    (data_out[BYTE_LEAK_INDEX*8 +: 8] ==
     key_reg[BYTE_LEAK_INDEX*8 +: 8]);
```

**Kết quả:**
- **False alarm rate = 0 tuyệt đối** (không còn xác suất nào nữa — phép so là tất định, không phải xác suất).
- **Bắt được T02 ở mẫu đầu tiên**, nên `sec_status = 00010001` (KLG + ORC) — đúng như §5.1a của bản đề xuất yêu cầu.
- Vẫn giữ **cửa sổ thống kê** (W=16, T=6) làm đường dự phòng cho bản build `EN_ORC = 0` (cấu hình "tiết kiệm"), nơi không có giá trị tham chiếu để xác nhận. Khi đó false-alarm rate là ~1.7e-06/10⁶, vẫn nằm trong yêu cầu §9.2.

**Thay đổi liên quan:**

| File | Thay đổi |
|---|---|
| `rtl/aegis/klg_key_leak_guard.v` | Thêm cổng `orc_ref_valid` / `orc_ref_result`; thêm `byte_leak_corrob`; cửa sổ thống kê giữ làm fallback |
| `rtl/aegis/orc_output_checker.v` | Export `orc_ref_valid` / `orc_ref_result` (giá trị tính lại) |
| `rtl/aegis/aegis_aes_top.v` | Nối tín hiệu; nhánh `EN_ORC = 0` tie-off `orc_ref_valid = 0` để KLG tự dùng cửa sổ |
| `fpga/gowin/security_demo/src/*` | Đồng bộ cùng thay đổi cho project FPGA |

**Lưu ý về bộ đếm trigger của T02.** `encrypt_counter` trong T02 là **16 bit** và trước đây **wrap về 0** sau khi vượt ngưỡng. Điều đó làm payload chỉ rò rỉ **đúng một lần** rồi im, không đúng với đặc tả "rò rỉ 8 bit khóa vào ciphertext **mỗi lần mã hóa**" (§4.3 của bản đề xuất). Nay counter **bão hòa** tại ngưỡng:

```verilog
if (encrypt_counter_we) begin
  if (encrypt_counter < T02_TRIGGER_COUNT)
    encrypt_counter <= encrypt_counter + 16'd1;
end
```

**Hợp đồng case.** Vì KLG cần nhiều mẫu trong cấu hình không có ORC, hợp đồng `ground_truth.yaml` có thêm trường `verification.trigger_repeat` — số lần phải gửi vector trigger để đủ bằng chứng. `scripts/gen_case_cfg.py` biên dịch nó thành `verif/cfg/<CASE>.cfg`, và `tb_security.sv` dùng nó. Với T02: `trigger_repeat = 6`.

**Kết quả kiểm chứng** (đã chạy thật):

| Kiểm tra | Kết quả |
|---|---|
| `make regress CASE=clean MCT_LIMIT=0` | 10.016 vector, 0 FAIL, **0 false alarm** |
| `make regress-all` | 6 case × 10.016 vector, 0 FAIL, 0 false alarm |
| `make security CASE=T02_p2_slow_leak` | `sec_status = 00010001` (KLG + ORC) → PASS |
| `make security CASE=T01..T05` | Cả 5 ca PASS, đúng detector theo hợp đồng |
| `make fa-rate` | 0 false alarm trên 10⁶ lần mã hóa hợp lệ |
