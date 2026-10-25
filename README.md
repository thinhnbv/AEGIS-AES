# AEGIS-AES — Trojan-Resilient AES-128 Core with On-Chip Security Monitors

AEGIS-AES wraps the open-source [secworks/aes](https://github.com/secworks/aes) AES-128
core with a set of hardware security monitors that detect malicious modifications
(hardware Trojans) in real time, while the core's standard AES functionality remains
verifiably intact (checked against NIST FIPS-197 vectors).

The repo contains both the intentional "infected" core variants — each with a
documented ground-truth contract — and the verification infrastructure that proves
the monitors catch every one of them.

## How it works

```
Layer 3 — FPGA demo (fpga/)          UART host <-> cmd FSM <-> aes_core_tapped
Layer 2 — Security wrapper (rtl/aegis/)  aegis_aes_top: 5 monitors + response unit
Layer 1 — Reference AES core (rtl/aes_golden/)  secworks/aes, unmodified
```

- `aegis_aes_top` wraps `aes_core_tapped`. Five monitors (KLG, FIC, RCM, RED, ORC)
  run **in parallel with the datapath** (they add no latency to encryption); a
  Tamper Response Unit (TRU) aggregates their alarms and responds with
  `NORMAL -> SUSPECT -> LOCKDOWN`: key zeroization and output blocking, only
  cleared by a hard reset.
- Five Trojan cases live in `rtl/infected/`. Each case ships a
  `ground_truth.yaml` that specifies the trigger, payload, and which monitor(s)
  must detect it. `make gen-cfg` compiles these contracts into
  `verif/cfg/*.cfg`, which the testbenches read at runtime.

| Case | Trojan payload | Detected by | `sec_status` |
|---|---|---|---|
| `T01_p1_key_dump` | Ciphertext replaced by the AES key | KLG + ORC | `00010001` |
| `T02_p2_slow_leak` | Key bytes leak after a large encryption count | KLG + ORC | `00010001` |
| `T03_p3_skip_mixcol` | MixColumns skipped at round 5 | RCM + ORC | `00010100` |
| `T04_p4_debug_port` | Unauthorized debug port exposes internal state | FIC + RED | `00001010` |
| `T05_dos_trojan` | Core hangs (denial of service) | RCM + RED | `00001100` |

Verified results: all 5 cases are detected by their contracted monitors with
zeroization + output blocking; the NIST FIPS-197 regression
(10,016 vectors per case) passes with no false alarms; the measured false-alarm
rate is 0 over 10⁶ valid encryptions.

## Repository layout

| Path | Contents |
|---|---|
| `rtl/aes_golden/` | Reference AES core (secworks/aes), kept unmodified |
| `rtl/aegis/` | Security wrapper: monitors, TRU, and the tapped core interface |
| `rtl/infected/` | Trojan case variants, each with `ground_truth.yaml` |
| `verif/` | Testbenches, NIST vectors, generated case contracts, SVA, UVM env |
| `fpga/` | Gowin GW5A-25 (ACG525) UART demo: plain AES and raw-vs-protected security demo |
| `docs/` | Architecture, repo guide, testplan, and project roadmap |
| `scripts/` | Vector generation, contract generation, validation helpers |

Detailed per-file notes, build steps, and known gotchas: [docs/REPO_GUIDE.md](docs/REPO_GUIDE.md).

## Requirements

- Icarus Verilog ≥ 11 (`iverilog`/`vvp`) — simulation
- Verilator ≥ 5.x — lint and the fast false-alarm benchmark
- Python 3 — contract and vector tooling
- ModelSim / Questa (Windows) — UVM + functional-coverage flow
- Optional: [SymbiYosys](https://symbiyosys.com/) (`sby`) for formal checks

All default targets run from the repository root.

## Quick start

```bash
make golden                     # reference core still produces correct AES output
make regress CASE=clean         # NIST FIPS-197 regression (KAT + 10,000 MCT vectors, ~10 min)
make regress CASE=clean MCT_LIMIT=100   # fast smoke test (~6 s)
make security CASE=T01_p1_key_dump      # one Trojan case: trigger it, check the detectors
make all-cases                  # all 5 Trojan cases (fails the target on any miss)
make regress-all                # NIST regression on the clean core + all 5 cases
make fa-rate SIM=verilator      # false-alarm rate over 10^6 valid encryptions (seconds on Verilator)
make lint                       # Verilator lint of the security wrapper
make formal                     # SymbiYosys bounded model check of the SVA set
```

## UVM verification environment (ModelSim)

A portable UVM testbench for the security wrapper lives in `verif/uvm/`
(UVM 1.2 core pinned as a submodule). Run it on Windows with ModelSim:

```bat
vsim -c -do "set aegis_case clean; do verif/uvm/scripts/aegis_uvm.tcl; quit"
vsim -c -do "set aegis_case T01_p1_key_dump; do verif/uvm/scripts/aegis_uvm.tcl; quit"
```

`aegis_case` accepts `clean`, `fa` (false-alarm rate), or any case name
(`T01_p1_key_dump` … `T05_dos_trojan`). Functional coverage is collected with
`-covd` and printed by `report coverage -functional`. See
[verif/uvm/README.md](verif/uvm/README.md) for the full flow, the capability
smoke test, and the coverage fallback.

## FPGA demo

Two Gowin GW5A-25 projects under `fpga/gowin/`:

- `aegis_demo` — plain AES-128 over UART (36/37-byte protocol, `fpga/host/test_uart.py`).
- `security_demo` — raw-vs-protected comparison: the same key/plaintext runs through
  an unprotected Trojan-infected core and through `aegis_aes_top`; the host CLI
  (`fpga/host/demo_cli.py`, 0xA5/0x5A protocol) shows the attack succeeding on the raw
  path while the protected path alarms and blocks output.

## Development notes

- Commit convention: work happens on `<type>/<topic>` branches
  (`verif/…`, `rtl/…`, `docs/…`, `fpga/…`) and is merged into `main`.
- `verif/cfg/*.cfg` are generated files — never edit by hand (`make gen-cfg`).
- The trigger vector pairs in `verif/vectors/` are duplicate real files
  (short + full case names); run `make check-vectors` after a fresh checkout.
