# UVM Verification Environment (ModelSim)

Môi trường UVM cho `aegis_aes_top` (5 monitor + TRU). Chạy trên
**ModelSim (Altera/Intel FPGA edition)** ở Windows; nguồn UVM là
[`accellera-official/uvm-core`](https://github.com/accellera-official/uvm-core)
pin tại tag **2020.3.1** (submodule `uvm-core/`).

## Cấu trúc

```
verif/uvm/
├── uvm-core/          # Accellera UVM 1.2 (submodule, pin 2020.3.1)
├── aegis_if.sv        # interface (không có clocking block - driver chạy @(negedge clk),
│                      #   khớp testbench plain-SV hiện có)
├── pkg/
│   ├── aegis_uvm_pkg.sv   # package wrapper (import uvm_pkg)
│   ├── aegis_txn.sv       # 1 transaction = 1 op (key/encrypt + expectation + captured result)
│   ├── aegis_spec.sv      # case spec: data đọc từ file (TB top làm file I/O, UVM class portable)
│   ├── aegis_agent.sv     # driver (handshake + capture) + monitor + sequencer
│   ├── aegis_seqs.sv      # nist_kat_seq / security_case_seq (T04 3-block, T02 repeat) / fa_rate_seq
│   ├── aegis_scoreboard.sv# KAT + detector mask + false-alarm check (duy nhất nguồn PASS/FAIL)
│   ├── aegis_coverage.sv  # covergroup thật (ModelSim -covd): op mix, sec_status pattern, latency
│   ├── aegis_env.sv
│   └── aegis_test.sv      # aegis_base_test (chọn seq theo spec.kind)
├── sva/
│   └── aegis_props.sv     # SVA bind vào aegis_aes_top (pulse, alarm sticky, no-output-after-alarm)
├── tb_top.sv            # DUT + clock/reset + TOÀN BỘ file I/O (cfg, vector, NIST) + run_test
└── scripts/
    └── aegis_uvm.tcl    # vlib/vlog/vsim -covd + report coverage -functional
```

## Chạy (Windows, từ repo root)

```bat
:: clean: NIST KAT + vector sạch, yêu cầu ciphertext đúng và KHÔNG có alarm giả
vsim -c -do "set aegis_case clean; do verif/uvm/scripts/aegis_uvm.tcl"

:: security case (T01..T05, trigger theo verif/cfg/<case>.cfg)
vsim -c -do "set aegis_case T03_p3_skip_mixcol; do verif/uvm/scripts/aegis_uvm.tcl"

:: false-alarm rate (1 key, nhiều block random - khớp make fa-rate)
vsim -c -do "set aegis_case fa; do verif/uvm/scripts/aegis_uvm.tcl"
```

Hoặc vào ModelSim GUI, Console: `do verif/uvm/scripts/aegis_uvm.tcl`
(có thể đặt `set aegis_case ...` trước).

Kết quả: scoreboard in `SUMMARY clean=… kat=… sec=… fail=0`; coverage xem
bằng `report coverage -functional` (đã có sẵn trong script) hoặc GUI
`Tools → Coverage Reports`.

## Chạy được trên Icarus không?

Không. Icarus không có UVM (class/sequence). UVM env này là flow
**ModelSim/Questa**; các testbench plain-SV hiện có
(`tb_security.sv`, `tb_regress_nist.sv`, `tb_fa_rate.sv`) tiếp tục
chạy trên Icarus/Verilator và là baseline đối chiếu: kết quả UVM phải
trùng với `make security` / `make regress` / `make fa-rate`.

## Capability smoke test (gate trước khi dựa vào ModelSim)

Trước khi coi ModelSim là công cụ DV chính, chạy 5 điểm kiểm tra
(theo `docs/DV_FPGA_PD_ROADMAP.md`, mục "Confirmed resources") và
ghi kết quả kèm version + lệnh:

| # | Kiểm tra | Cách | Đạt khi |
|---|---|---|---|
| 1 | UVM startup | `aegis_smoke_test` (hoặc chạy `case=clean` với 1 vector) | `run_test` kết thúc, UVM test report in ra |
| 2 | Constrained-random + seed reproducible | `fa` case, ghi seed từ log; chạy lại cùng seed | cùng chuỗi block, cùng kết quả |
| 3 | SVA pass + SVA fail chủ ý | compile `-assert`; trên clean: 0 violation; tạo 1 input vi phạm (vd giữ `key_valid` 2 chu kỳ) | assert bắt được |
| 4 | Functional coverage sampling | chạy `case=clean`, `report coverage -functional` | có dòng coverpoint, % hit |
| 5 | Save/merge/report DB | `save_covd` + chạy case khác + `report coverage -functional` | DB gộp được |

**Nếu #4/#5 bị chặn license** (edition ModelSim của bạn không có
functional coverage): fallback — giữ UVM + SVA như bình thường, thay
`aegis_coverage.sv` bằng UVM event-counter (không dùng covergroup) +
code coverage Verilator (`--coverage -ccov`). UVM/SVA không bị ảnh
hưởng. Ghi kết quả smoke test vào `verif/uvm/SMOKE_RESULTS.md`.

## Ghi chú thực thi

- `tb_top.sv` dùng hierarchical reference `u_dut.u_core.*` cho T02
  counter preload — chỉ chạy trên simulator (ModelSim/Questa/Icarus),
  KHÔNG chạy trên OpenLane (giống quy tắc đã biết trong REPO_GUIDE).
- SVA dùng subset portable (immediate + `|->` + `disable iff`) để chạy
  được cả ModelSim lẫn formal (SymbiYosys qua `verif/sva/aegis.sby`).
- SVA P4 (alarm sticky) và P7 (request eventually completes) là
  candidate cho `make formal` (BMC bounded depth).
