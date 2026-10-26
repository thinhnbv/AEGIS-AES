# UVM Verification Environment (ModelSim)

Môi trường UVM cho `aegis_aes_top` (5 monitor + TRU), chạy trên
**ModelSim 2020.1 (Intel FPGA Starter edition)** với
[Accellera UVM 1.2](https://github.com/accellera-official/uvm-core)
pin tag **2020.3.1** (submodule `uvm-core/`).

Toolchain hiện dùng cho flow UVM:

- UVM env chỉ chạy trên ModelSim/Questa — Icarus không có UVM, và
  Verilator (5.020) không compile được UVM 1.2 (đã kiểm tra,
  `%Error-PKGNODECL` ở factory/`type_id`).
- Bản Starter không có license Code Coverage → build **default** của
  `aegis_coverage.sv` dùng event counters (không cần license); build
  covergroup thật chỉ chạy trên Questa: `-DAEGIS_COVGROUP` +
  `vsim -covd`.
- Kết quả UVM phải trùng baseline plain-SV: `make security` /
  `make regress` / `make fa-rate` (Icarus/Verilator, xem
  `docs/REPO_GUIDE.md` mục 8).

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
│   ├── aegis_coverage.sv  # default: event counters; -DAEGIS_COVGROUP: covergroup (Questa)
│   ├── aegis_env.sv
│   └── aegis_test.sv      # aegis_base_test (chọn seq theo spec.kind)
├── sva/
│   └── aegis_props.sv     # SVA bind vào aegis_aes_top (pulse, alarm sticky, no-output-after-alarm)
├── tb_top.sv            # DUT + clock/reset + TOÀN BỘ file I/O (cfg, vector, NIST) + run_test
└── scripts/
    └── aegis_uvm.tcl    # vlib/vlog -sv + vsim -c (kèm -coverage nếu bản có license)
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

Kết quả mong đợi: scoreboard in `SUMMARY clean=… kat=… sec=… fail=0`
và report event-counter (build default). Bản Questa chạy thêm
`report coverage -functional`.

## Ghi chú khi sửa env (UVM 1.2, không phải UVM 1.1)

- Connect: `drv.seq_item_port.connect(sqr.seq_item_export)`.
- Driver/sequencer cùng parameter `(aegis_txn, aegis_txn)`.
- `seq_item_port.get_next_item(txn)` (1.1: `get_next_request`).
- Constructor UVM class đóng bằng `endfunction`; không declare biến
  giữa thân task đã có statement (ModelSim bắt, Icarus thì cho).

## Ghi chú thực thi

- `tb_top.sv` dùng hierarchical reference `u_dut.u_core.*` cho T02
  counter preload — chỉ chạy trên simulator (ModelSim/Questa/Icarus),
  KHÔNG chạy trên OpenLane (giống quy tắc đã biết trong REPO_GUIDE).
- SVA dùng subset portable (immediate + `|->` + `disable iff`) để chạy
  được cả ModelSim lẫn formal (SymbiYosys qua `verif/sva/aegis.sby`).
- SVA P4 (alarm sticky) và P7 (request eventually completes) là
  candidate cho `make formal` (BMC bounded depth).
