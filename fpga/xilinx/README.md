# AEGIS-AES trên Zynq ZC702 (xc7z020clg484-1)

Port demo UART của `fpga/gowin/security_demo` sang board **ZC702**:
cùng `uart_cmd_fsm_security` (gồm watchdog T05), cùng giao thức
0xA5/0x5A, nhưng clock là **SYSCLK LVDS 200 MHz on-board** (chia ÷8
bởi bộ chia RTL trong top → fabric chạy **25 MHz**, không cần MMCM)
và bộ
source dùng **master `rtl/aegis`** (KLG full + ORC + cổng `fsm_state`
rõ, không tham chiếu phân cấp — hợp lệ cho ASIC/PnR thật).

**Mỗi ca Trojan = 1 bitstream riêng** (chỉ `aes_core_tapped.v` đổi;
protected path giống nhau).

## Nguồn (source set)

| Nhóm | File | Lấy từ |
|---|---|---|
| Top | `top_security_demo.v` | `fpga/xilinx/` (LVDS pair `clk_p`/`clk_n` — Vivado tự suy buffer IBUFDS theo XDC, KHÔNG instantiate thủ công; bộ chia ÷8 → `CLK_FREQ=25_000_000`) |
| XDC | `zc702.xdc` | `fpga/xilinx/` (pin map UG850/RDF0171, `LVDS_25` cho cặp clock) |
| UART + FSM | `uart_rx.v` `uart_tx.v` `uart_cmd_fsm_security.v` (có watchdog T05) | `fpga/gowin/security_demo/src/` (sync tự động trong build) |
| AEGIS wrapper | `aegis_aes_top.v` + 5 monitor + TRU + 2 block/KeyMem + `aegis_defs.vh` | `rtl/aegis/` (master) |
| S-box/InvS-box/Decipher | `aes_sbox.v` `aes_inv_sbox.v` `aes_decipher_block.v` | `rtl/aes_golden/` |
| Core nhiễm (đổi theo ca) | `aes_core_tapped.v` | `rtl/infected/<CASE>/` |

`build_zynq.tcl` tự đồng bộ source vào `src/` bằng TCL `file copy`
(cùng danh sách với `sync_sources.sh`) — **không cần chạy script
ngoài**, chạy 1 lệnh Vivado là đủ.

## Pin map (ZC702, đã đối chiếu reference XDC/UCF của board)

| Tín hiệu | Ball | I/O standard |
|---|---|---|
| `clk_p` / `clk_n` (SYSCLK 200 MHz) | D18 / C19 | LVDS_25 |
| `rst_n` (DIP SW5, active-low) | G19 | LVCMOS25 |
| `uart_rx` (PMod2 pin 3) | P18 | LVCMOS25 |
| `uart_tx` (PMod2 pin 2) | W10 | LVCMOS25 |
| `led[0] led[1] led[2] led[3]` (PMod1) | E15 / D15 / W17 / W5 | LVCMOS25 |

Khuyến cáo: **tránh pin chẵn J63** (PJTAG).

## Thiet bi VM Vivado (git pull - khong can chung file)

Tat ca file "that" cua project nam trong repo (branch
`fpga/xilinx-zc702-demo`). Thu muc `fpga/xilinx/src/` la **sinh ra**
boi `sync_sources.sh` (Linux/WSL) hoac `sync_sources.bat` (Windows),
da .gitignore — khong commit.

### 1) Tren WSL (repo) — push 1 lan

```bash
git push origin fpga/xilinx-zc702-demo
```

### 2) Tren Windows/VM (bat file) — clone 1 lan, sau do pull

```bat
git clone -b fpga/xilinx-zc702-demo https://github.com/thinhnbv/AEGIS-AES.git C:\VM_Xilinx\zynq-aegis
cd C:\VM_Xilinx\zynq-aegis
:: cac lan sau:
git pull
```

### 3) Sinh source set cho 1 ca (khong can WSL, dung .bat)

```bat
fpga\xilinx\sync_sources.bat T01_p1_key_dump
:: hoac ca khac:
fpga\xilinx\sync_sources.bat T05_dos_trojan
```

Ket qua: `fpga\xilinx\src\` = 17 file `.v` + `aegis_defs.vh` +
`cores\` (5 core trojan de swap khi chay GUI). Moi lan doi ca =>
chay `sync_sources.bat` lai (`src/` duoc ghi de).

## Bước 1 — Chạy Synthesis + PnR (VM có Vivado 2024.1)

### Cách A (khuyến nghị, 1 lệnh 1 ca)

Tu `C:\VM_Xilinx\zynq-aegis\` (bat file phai nam ngang
`build_zynq.tcl`, vi script tu dinh duong bang `info script`):

```bat
:: 1 ca:
vivado -mode batch -nolog -nojournal -source build_zynq.tcl -tclargs T01_p1_key_dump
:: hoac khong dung -tclargs (moi truong):
set AEGIS_CASE=T01_p1_key_dump && vivado -mode batch -nolog -nojournal -source build_zynq.tcl
```

Cả 5 ca: chạy `run_all.bat`.

Mỗi ca ra (trong `C:\VM_Xilinx\zynq-aegis\`):

```
aegis_<CASE>\               # project Vivado + runs
reports\<CASE>\             # util.rpt, timing.rpt, timing_min.rpt,
                             # methodology.rpt, clock_util.rpt
aegis_<CASE>\impl_1\*.bit   # bitstream (nang len board)
```

### Cách B — GUI từng bước (nếu muốn xem report trực quan)

1. Mở **Vivado → Create New Project** → part: **xc7z020clg484-1**.
2. **Add Sources**:
   - `fpga/xilinx/src/*.v` (17 file .v)
   - `fpga/xilinx/src/aegis_defs.vh` (đánh dấu *Header/File Include*)
   - `fpga/xilinx/zc702.xdc` (Add as: *Constraint*)
3. **Sources → Set Top**: `top_security_demo`.
4. **Run Synthesis** (phím F11) → chờ hết.
5. **Run Implementation** (chọn **Generate Post-Place-and-Route
   Static Report**, không cần bitstream bước thử) → chờ hết.
6. Xem report: **Reports** tree hoặc tab ở cuối log
   (`Utilization Methodology Report`, `POST_ROUTE_PARITY_2N`… ).
7. Chạy lại bước 4–5 cho ca khác (đổi `aes_core_tapped.v` — chạy
   `sync_sources.sh <CASE>` nếu chạy ngoài TCL).

## Bước 2 — Đọc report (bằng chứng "đã chạy thật")

### `reports/<CASE>/util.rpt` — tài nguyên

Chú ý 3 dòng đầu bảng *Slice Logic* (dự kiến, cần đối chiếu thật):

- **LUT (with LUT as Logic Element)** — % Slice LUT
- **FF** — % Slice Register
- **BRAM** — **phải = 0** (bộ RAM AES 1408 bit nhỏ, tool sẽ
  triển ra LUT; nếu > 0 kiểm tra có BRAM IP nào bị lỡ ràng buộc).
- **DSP48E1 = 0**.

### `reports/<CASE>/timing.rpt` — timing (chu kỳ 40 ns = 25 MHz)

Đường critical ~28.7 ns (tree so 128-bit của KLG) nên **fabric chạy
25 MHz** (bộ chia ÷8 trong top, nguồn 200 MHz chỉ đi qua IBUFDS +
counter chia). `zc702.xdc` ràng `create_generated_clock -name clk25`
trên `div_cnt_reg[2].Q`.

Xem 2 dòng cuối section *Design Timing Summary* ở **cả 2 clock**:

- **`clk` (200 MHz, 5 ns)** — chỉ IBUFDS + bộ chia: WNS phải ≥ 0.
- **`clk25` (25 MHz, 40 ns)** — toàn bộ fabric: WNS phải ≥ 0
  (dư ~11 ns margin; đây là clock định mệnh).
- **WHN (ns)** — hold, phải ≥ 0 ở tần số bất kỳ.

Nếu **WNS < 0 ở `clk25`** (không khả thi — 28.7 < 40 ns — nhưng
nếu đổi bộ chia): tăng ÷ (vd ÷16 → 12.5 MHz, UART vẫn ổn).
Xem backup 50 MHz source ÷2 trong `zc702.xdc`.

Nếu PnR lỗi *"pin div_cnt_reg[2].Q không tìm thấy"* (tên register
bị tổng hợp đổi): xóa dòng `create_generated_clock` khỏi XDC —
Vivado vẫn tự suy clock chia, timing tiếp tục được phân tích
(dòng XDC chỉ để đặt tên + chu kỳ rõ cho report).

### `methodology.rpt`

Các *warning* thường thấy (không chặn bitstream): "clock net
created by non-buffer", "IOB pin not driven by IBUF" (cùng với
LVDS_25 cho clock), "multi-driver". Chỉ cần **không có error**
ở báo cáo PnR.

## Bước 3 — Nạp bitstream lên board

1. Board cắm **USB JTAG** (J10) + **USB-UART** vào PMod2:
   - USB-UART TX → P18 (PMod2 pin 3, `uart_rx` của thiết kế)
   - USB-UART RX → W10 (PMod2 pin 2, `uart_tx` của thiết kế)
   - GND (PMod2 pin 4/5) nối chung
2. **Vivado → Open Hardware Manager** → `Open Target → Auto Scan`.
3. `Program Device` → chọn `impl_1/*.bit` của ca đang demo.
4. Nhấn nút **DIP SW5** 1 lần (reset thiết kế, active-low có pullup).

## Bước 4 — Demo trên máy chủ (5 ca Trojan, 1 lệnh 1 ca)

Trên PC chạy `fpga/host/demo_cli.py` (driver COM cho USB-UART,
baud **115200 8N1**). Mỗi ca = 1 lệnh `case T0x` — lệnh này tự động
gửi clean baseline + trigger sequence đúng ca + kiểm tra detector
mask + TRU lockdown + frame post-lockdown, rồi in `[PASS]`:

```bash
# Nạp bitstream của ca (Bước 3), rồi:
python3 fpga/host/demo_cli.py --port COM5 case T01   # key dump
python3 fpga/host/demo_cli.py --port COM5 case T02   # slow leak (65552 frame, ~5-8 phút)
python3 fpga/host/demo_cli.py --port COM5 case T03   # skip MixColumns
python3 fpga/host/demo_cli.py --port COM5 case T04   # debug port (3 frame A5->5A->FF)
python3 fpga/host/demo_cli.py --port COM5 case T05   # DoS (watchdog FSM cứu)

# Chi tiết hơn:
python3 fpga/host/demo_cli.py --port COM5 case T02 --repeat 70000
python3 fpga/host/demo_cli.py --port COM5 case T05 --no-clean
python3 fpga/host/demo_cli.py --port COM5 clean      # baseline FIPS-197
python3 fpga/host/demo_cli.py --port COM5 random --count 1000
```

Lưu ý T02: `--repeat` (mặc định `T02_DEFAULT_REPEAT=65552`) phải lớn
hơn ngưỡng kích hoạt `2^16` của counter trong core nhiễm; mỗi frame
~73 byte @ 115200 = ~6.4 ms nên 65552 frame ≈ 7 phút (chưa kể
bắt buộc phải chờ protected FSM hoàn tất mỗi lượt). Có thể
`--repeat 131072` nếu muốn đếm đủ 2^17 cho chắc.

### Bảng kết quả kỳ vọng (hợp đồng `rtl/infected/*/ground_truth.yaml`)

| Ca | Detector bắt (hợp đồng `verif/cfg/*.cfg` của branch) | `sec_status` (protected) | Raw path (không che) |
|---|---|---|---|
| T01 | KLG | `0x01` | `raw_out = key` (128 bit, không phải ciphertext) |
| T02 | KLG | `0x01` | byte thấp = `key[7:0]` sau 2^16 lần mã hóa (ORC cũng có thể lên, không bắt buộc) |
| T03 | RCM + ORC | `0x14` | ciphertext sai (bỏ MixColumns ở round cuối) |
| T04 | FIC + RED | `0x0A` | `raw_out` không sai nhưng debug port lộ state |
| T05 | RCM | `0x04` | `RAW_VALID = 0` (core hang, watchdog FSM cứu) |

> Ghi chú: `verif/cfg` trên branch này là `make gen-cfg` sinh từ
> `ground_truth.yaml`; mask trên khớp đúng `CASE_CONTRACT` trong
> `fpga/host/demo_cli.py`. Nếu merge contract mới hơn (vd T02 =
> KLG+ORC `0x11`), phải cập nhật cả 2 nơi.

Trước khi kích hoạt ca: `sec_status = 0x00`, `flags = 0x05`
(`RAW_VALID`+`PROTECTED_VALID`), `raw_out == protected_out == FIPS-197`.

## Các lệnh kiểm tra song song trên WSL (không cần board)

```bash
# Chứng minh "sự thật tính năng" - hợp đồng 5 ca trên sim
make security CASE=T01_p1_key_dump SIM=verilator
make security CASE=T02_p2_slow_leak SIM=verilator TRIG_REPEAT=65536
make security CASE=T03_p3_skip_mixcol SIM=verilator
make security CASE=T04_p4_debug_port SIM=verilator
make security CASE=T05_dos_trojan SIM=verilator

# Chạy "demo proof" byte-level trên bộ source XILINX (chính source
# Vivado sẽ build - chứng minh bộ file hợp lệ ở tầng chức năng).
# Top KHONG con su dung primitive IBUFDS (Vivado tu suy buffer theo
# XDC nen source set trong sach, khong can stub).
iverilog -g2012 -I fpga/xilinx/src -DT03 \
  fpga/xilinx/src/*.v fpga/xilinx/src/aegis_defs.vh \
  fpga/gowin/security_demo/tb/tb_uart_demo.sv -o /tmp/zc_T03.out
vvp /tmp/zc_T03.out
```

## Rủi ro / ghi chú

- **PMod qua level-shifter (TXS0108E)**: UART 115200 + LED là tần số
  thấp → an toàn. Không đưa clock 200 MHz qua PMod (chỉ dùng SYSCLK
  LVDS on-board cho clock).
- **J63 chẵn = PJTAG**: tuyệt đối không dùng pin chẵn (even number)
  của header J63; LED PMod1 đã chọn ở ball lẻ (E15, D15, W17, W5).
- **BRAM dự kiến 0**: nếu report hiện BRAM > 0, kiểm tra `aes_key_mem_tapped.v`
  (danh sách round key) có được ràng buộc thành BRAM không (mặc định
  là LUT, đúng thiết kế Secworks).
- **Timing đã khóa ở 25 MHz** (fabric qua bộ chia ÷8; nguồn 200 MHz
  chỉ IBUFDS + counter chia): WNS âm ở `clk25` = phải tăng bộ chia
  (÷16 → 12.5 MHz, UART error vẫn 0.006%) — xem Bước 2.
- **Watchdog FSM ở 25 MHz**: `RAW_TIMEOUT`/`PROT_TIMEOUT` = 65535
  chu kỳ = ~2.6 ms (trước đây ~0.33 ms ở 200 MHz) — demo không
  bị ảnh hưởng (T05 vẫn được watchdog cứu, chỉ chậm hơn).
- Source Xilinx **sync mỗi lần build** (TCL tự chạy) nên không bao giờ
  cũ — khác bản copy Gowin (phải đồng bộ thủ công, xem CLAUDE.md).
