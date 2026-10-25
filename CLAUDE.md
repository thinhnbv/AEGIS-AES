# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Quy tắc commit (bắt buộc)

**Không được thêm bất kỳ trailer tác giả phụ nào vào commit message.** Repo này chỉ có `thinhnbv` là author — commit chỉ ghi tên tác giả chính, không ghi thêm dòng trạng thái "co-authored"/"co-generated" cho bất kỳ công cụ hay trợ lý nào. Không có ngoại lệ.

Quy tắc này áp dụng cho **cả nội dung file**: không viết dòng dạng đó vào source, comment, hay tài liệu nào trong repo (kể cả chính file này).

Nếu đã lỡ thêm vào commit message, xóa khỏi **toàn bộ lịch sử** (không chỉ commit mới):

```bash
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f \
  --msg-filter 'sed -E "/^[Cc]o-[Aa]uthored-[Bb]y: /d; /^[Cc]o-[Gg]enerated-[Bb]y: /d"' \
  --tag-name-filter cat -- --all

# filter-branch giữ lại bản gốc trong refs/original/ - phải xoá, nếu không
# trailer vẫn còn trong database:
git for-each-ref --format='%(refname)' refs/original | while read r; do git update-ref -d "$r"; done
git reflog expire --expire=now --all && git gc --prune=now
```

Sau khi rewrite, lịch sử đã đổi SHA → cần `git push --force-with-lease` cho mọi branch. Kiểm tra lại bằng:

```bash
git log --format="%B" --all | grep -iE "^Co-(Authored|Generated)-By:"
```

Lệnh trên phải cho ra **không có dòng nào**.

## Dự án này là gì

AEGIS-AES là lõi AES-128 bị cấy hardware Trojan có chủ đích, kèm bộ **security monitor on-chip** phát hiện Trojan đó theo thời gian thực mà không sửa core AES gốc. Quy trình phát triển là vòng lặp **Red team / Blue team** có trợ giúp LLM: Red team cấy Trojan vào bản copy core (`rtl/infected/`), Blue team viết khối giám sát (`rtl/aegis/`) để bắt được nó mà vẫn giữ được chức năng AES chuẩn (kiểm bằng vector NIST FIPS-197).

Ba lớp, từ dưới lên:

```
Lớp 3 — Demo FPGA (fpga/)            UART 115200 8N1 ⇄ uart_cmd_fsm ⇄ aes_core_tapped
Lớp 2 — Security wrapper (rtl/aegis/)  aegis_aes_top + KLG/FIC/RCM/RED/ORC + TRU
Lớp 1 — Core AES tham chiếu (rtl/aes_golden/)  secworks/aes, BẤT BIẾN
```

Chi tiết đầy đủ: [`docs/REPO_GUIDE.md`](docs/REPO_GUIDE.md). Bảng tín hiệu tap: [`docs/architecture.md`](docs/architecture.md).

## Lệnh thường dùng

Tất cả chạy từ thư mục gốc repo.

```bash
make golden                                  # core AES gốc còn nguyên vẹn (baseline)
make security CASE=T02_p2_slow_leak         # một ca Trojan: trigger, đo detector nào bắt
make all-cases                               # security cho cả 5 ca
make regress CASE=clean                      # NIST FIPS-197: KAT 16 + MCT 10.000 (~10 phút)
make regress CASE=clean MCT_LIMIT=100       # smoke test nhanh (~6 giây)
make regress-all                             # NIST regression cho clean + 5 ca
make fa-rate SIM=verilator FA_KEYS=200 FA_PER_KEY=5000   # đo false-alarm rate trên 10^6 mã hóa
make gen-cfg                                 # sinh lại verif/cfg/*.cfg từ ground_truth.yaml
make lint                                    # Verilator lint trên rtl/aegis
```

`make fa-rate` mặc định dùng Icarus — **cần vài giờ** cho 10⁶ mã hóa. Luôn dùng `SIM=verilator` (compiled C++, chạy vài giây).

Chạy một testbench lẻ: `make sim CASE=T01` dùng `verif/tb/tb_<CASE>.sv` nếu có, không thì `tb_aegis_top.sv`.

## Kiến trúc cần biết để làm việc

### `rtl/aes_golden/` — bất biến

Core Secworks nguyên bản. **Không sửa trực tiếp.** Muốn thêm cổng debug hoặc cấy Trojan → copy sang `rtl/aegis/*_tapped.v` hoặc `rtl/infected/Txx.../` rồi sửa bản copy.

### `rtl/aegis/` — RTL của nhóm

`aegis_aes_top.v` bọc `aes_core_tapped`, điều phối FSM 6 trạng thái. Sáu khối giám sát chạy **song song, không nằm trên đường trễ chính**:

| Module | Bắt được gì |
|---|---|
| `klg_key_leak_guard.v` | Khoá lộ ra `data_out` (so 128-bit, so lát 32-bit, Hamming bất thường, và so lát 8-bit **có xác nhận bằng ciphertext tham chiếu của ORC**) |
| `fic_fsm_integrity.v` | FSM nội bộ rời tập trạng thái hợp lệ (one-hot check) |
| `rcm_round_monitor.v` | Round counter bị skip / lặp / kết thúc sai round |
| `orc_output_checker.v` | Tính lại round cuối độc lập rồi so — bắt mọi sai lệch 1 bit |
| `red_rare_event.v` | Cảnh báo **mềm**: plaintext hằng số đặc biệt, pattern tuần tự, counter ngưỡng |
| `tru_tamper_response.v` | FSM `NORMAL → SUSPECT → LOCKDOWN`; ở LOCKDOWN thì zeroize + chặn `data_out`, chỉ thoát bằng reset cứng |

`sec_status` là bitmask 8 bit, bit thứ tự: KLG, FIC, RCM, RED, ORC.

**Quan trọng — KLG dùng ORC để xác nhận.** Lớp dò rò rỉ 8-bit so `data_out[7:0]` với `key_reg[7:0]`. Nếu chỉ so thế, xác suất trùng ngẫu nhiên là 1/256 mỗi lần mã hóa → ~3906 false alarm trên 10⁶, và full regression NIST 10.000 vector **treo ở vector 266** (core sạch). Nay KLG nhận `orc_ref_valid` / `orc_ref_result` từ ORC: byte chỉ được coi là rò rỉ khi core thực sự đã sửa nó (`ct != orc_ref && ct == key`). Kết quả: **false alarm = 0 tuyệt đối**, T02 vẫn bị cả KLG lẫn ORC bắt. Cửa sổ thống kê (W=16, T=6) giữ lại làm đường dự phòng cho build `EN_ORC=0` — nhánh đó phải tie-off `orc_ref_valid = 0`.

**Hierarchical reference.** `aegis_aes_top.v` dùng `u_core.aes_core_ctrl_reg` cho FIC. Cách này chạy được với simulation/FPGA nhưng **không** chạy được với ASIC backend (OpenLane) — cần port tường minh.

### `rtl/infected/` — ca Trojan

Mỗi thư mục `T0x_<tên>` là một ca độc lập: bản copy core đã cấy 1 Trojan, kèm `ground_truth.yaml` mô tả Trojan đó. `aes_core.v` trong đó là **bản copy chưa nhiễm** — Trojan nằm ở `aes_core_tapped.v` cùng thư mục (Makefile đã `filter-out` file đó).

`ground_truth.yaml` là **hợp đồng** giữa Red team và Blue team: `detection.expected_checker` cho biết detector nào **phải** bắt được ca này, `verification.silent_under_nist` cho biết Trojan có phải im lặng trên traffic NIST không, `verification.trigger_repeat` cho biết cần gửi vector trigger bao nhiêu lần để đủ bằng chứng.

### Hợp đồng case dạng phẳng

Testbench không đọc YAML được. `scripts/gen_case_cfg.py` biên dịch `ground_truth.yaml` → `verif/cfg/<CASE>.cfg` (mỗi ca có 2 file: tên ngắn `T01.cfg` và tên đầy đủ `T01_p1_key_dump.cfg`).

**`verif/cfg/*.cfg` không sửa tay** — chạy `make gen-cfg`. `verif/tb/aegis_cfg_reader.vh` là task đọc file lúc chạy, dùng chung bởi `tb_security.sv` và `tb_regress_nist.sv`. Nhờ vậy Red team và Blue team không thể lặng lẽ hiểu sai nhau.

Cấu trúc `aegis_cfg_read` (thêm/bớt đối số thì phải sửa **cả** task lẫn mọi nơi gọi):

```verilog
aegis_cfg_read(cfg_path, cfg_mask, cfg_latency, cfg_silent, cfg_repeat, cfg_ok);
```

### `verif/`

- `tb_security.sv` — kịch bản an ninh: một lượt "clean" + một lượt "trigger", so detector có phản ứng đúng hợp đồng không, rồi kiểm tra zeroize/LOCKDOWN/chặn output.
- `tb_regress_nist.sv` — regression NIST FIPS-197. Với **mỗi** vector kiểm 2 tính chất: (1) ciphertext đúng chuẩn, (2) không monitor báo động giả.
- `tb_fa_rate.sv` — đo false-alarm rate trên lưu lượng hợp lệ (1 key dùng lại nhiều lần — khác `tb_regress_nist` vốn đổi key mỗi vector nên không đo được tầng cửa sổ).
- `verif/vectors/` — mỗi dòng `<key> <plaintext> <ciphertext>` (32 ký tự hex). Trường thứ 3 là ciphertext AES-128 **chuẩn** dùng làm tham chiếu — ngoại lệ duy nhất là `trigger_T01.txt` (payload P1 thay ciphertext bằng chính khoá, nên `expected` cố ý là giá trị khoá).
- **Symlink**: mỗi ca có 2 tên file vector, 1 là symlink trỏ file kia. Sửa vector → sửa file chứa dữ liệu thật, không sửa symlink.

### `fpga/` — nhiều bản sao song song, dễ sửa nhầm

Project chính là `fpga/gowin/security_demo/` (`top_security_demo.v`, giao thức UART `0xA5`/`0x5A`, khớp `fpga/host/demo_cli.py`).

Có **hai top module với hai giao thức khác nhau** — đừng nhầm:

| | `top_demo.v` (cũ) | `top_security_demo.v` (chính) |
|---|---|---|
| Security monitor | ❌ | ✅ |
| Preamble | `0x01`/`0x02` | `0xA5`/`0x5A` |
| Script PC | `test_uart.py` | `demo_cli.py` |
| Project Gowin | `aegis_demo/` | `security_demo/` |

`uart_cmd_fsm.v` và `uart_cmd_fsm_security.v` là **hai module khác nhau cố ý khác nhau** — đừng "đồng bộ" chúng.

Nguồn UART bị nhân bản: sửa bug UART phải sửa **cả** `fpga/uart/uart_rx.v` + `uart_tx.v` **và** `fpga/gowin/security_demo/src/`. Tương tự `rtl/aegis/*.v` bị copy vào `fpga/gowin/security_demo/src/` — sửa RTL ở `rtl/aegis/` thì phải copy sang đó.

`fpga/Makefile` trỏ toolchain Linux không tồn tại trên máy Windows — dùng task VSCode (`.vscode/tasks.json`) thay thế.

### `sec_status` bitmask

Bit 0 = KLG, 1 = FIC, 2 = RCM, 3 = RED, 4 = ORC. Kỳ vọng từng ca:

| Ca | Detector | `sec_status` |
|---|---|---|
| T01 key dump | KLG + ORC | `00010001` |
| T02 slow leak | KLG + ORC | `00010001` |
| T03 skip MixColumns | RCM + ORC | `00010100` |
| T04 debug port | FIC + RED | `00001010` |
| T05 DoS | RCM + RED | `00001100` |

## Cạm bẫy đã biết

- **`verif/cfg/*.cfg` là file sinh tự động.** Sửa tay sẽ bị `make gen-cfg` ghi đè.
- **Vector có symlink.** Sửa file chứa dữ liệu thật.
- **Bản copy RTL trong `fpga/`** phải đồng bộ thủ công với `rtl/aegis/`.
- **Merger branch hay gây trùng khai báo biến** trong `verif/tb/tb_security.sv` (cả hai bên đều khai báo `cfg_*`). Sau khi merge phải compile lại toàn bộ, không tin vào việc merge "sạch".
- **`make formal` chưa chạy được** — `verif/sva/aegis.sby` chưa tồn tại, cần cài `sby`.
- **`make campaign` / `report` / `backend` chưa chạy được** — `platform/`, `scripts/report.py`, `backend/openlane/` chưa tồn tại trong repo.
- **Chưa có ràng buộc `create_clock`** cho `clk` trong constraint file → phân tích timing chưa chính xác.
- `tb_regress_nist.sv` **đổi key mỗi vector** → cửa sổ detector không bao giờ tích luỹ. Đừng dùng nó để đo false-alarm rate; dùng `tb_fa_rate.sv`.

## Quy ước

- **Tiếng Việt không dấu trong comment/tài liệu** — repo hiện dùng kiểu này xuyên suốt. Match theo file đang sửa.
- Nhánh theo dạng `<loại>/<nội dung>`: `verif/…`, `rtl/…`, `docs/…`, `fpga/…`.
- Commit message: tiêu đề dạng `type(scope): mô tả ngắn`, thân giải thích **vì sao** chứ không chỉ **cái gì** thay đổi. Ghi kèm số liệu kiểm chứng nếu có.
- **Mọi khẳng định "đã kiểm chứng" phải kèm lệnh chạy thật.** README và `docs/REPO_GUIDE.md` ghi rõ lệnh kiểm chứng cho từng mục — giữ nguyên thông lệ đó.
- Ưu tiên sửa **nguồn** (`rtl/aegis/`) rồi đồng bộ bản copy, thay vì sửa bản copy rồi quên nguồn.
