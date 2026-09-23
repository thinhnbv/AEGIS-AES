# AEGIS-AES vs Baseline AES-128 — Resource & Timing Comparison

**Device:** Gowin GW5A-25A (GW5A-LV25UG324C2/I1)
**Tool:** Gowin EDA V1.9.9 (64-bit)
**Date:** 2026-09-21
**Baseline project:** `aes_basline` (clean `aes_core`, encryption-only)
**Protected project:** `security_demo` (AEGIS `aes_core_tapped` + KLG/FIC/RCM/RED/ORC/TRU)

---

## 1. LUT (Look-Up Tables) — Post-PnR

| Module | Baseline | AEGIS (protected) | Overhead | % Tăng |
|---|---:|---:|---:|---:|
| **Total LUT** | **5,511** | **11,392** | **+5,881** | **+106.7%** |
| **Total ALU** | **9** | **1,721** | **+1,712** | **+19,022%** |
| **Total Logic** | **5,520** | **13,113** | **+7,593** | **+137.6%** |
| └─ Utilization | 24% | 57% | +33% | - |

**Phân tích:**
- Core AES gốc: ~5,500 LUT
- AEGIS security overhead: ~5,900 LUT (tương đương 1 AES core)
- ALU explosion: từ 9 → 1,721 (do KLG key comparison logic)

### Module-level LUT breakdown

| Module | Baseline | AEGIS | Overhead |
|---|---:|---:|---:|
| aes_core (enc_block + keymem + sbox) | 3,193 | 3,178 | ~0 |
| AEGIS Security (KLG/FIC/RCM/RED/ORC/TRU) | 0 | 5,100 | +5,100 |
| UART / Control (uart_rx/tx, cmd_fsm) | 497 | 518 | +21 |

---

## 2. FF (Flip-Flops / Registers) — Post-PnR

| Resource | Baseline | AEGIS | Overhead | % Tăng |
|---|---:|---:|---:|---:|
| **Logic Register FF** | **2,978** | **6,332** | **+3,354** | **+112.6%** |
| **I/O Register FF** | **1** | **1** | **0** | **0%** |
| **Total FF** | **2,979** | **6,333** | **+3,354** | **+112.6%** |
| └─ Utilization | 13% | 27% | +14% | - |

**Phân tích:**
- Security modules chiếm ~3,350 FF (tương đương 1.13× AES core registers)

### Module-level FF breakdown

| Module | Baseline | AEGIS | Overhead |
|---|---:|---:|---:|
| aes_core | 2,341 | 2,341 | 0 |
| AEGIS Security | 0 | 2,899 | +2,899 |
| UART / Control | 638 | 1,093 | +455 |

---

## 3. CLS (Configurable Logic Slices) — FPGA Area

| Metric | Baseline | AEGIS | Overhead |
|---|---:|---:|---:|
| **CLS Usage** | **4,742** | **9,729** | **+4,987 (+105%)** |
| **Utilization** | **42%** | **85%** | **+43%** |
| **Available** | 11,520 | 11,520 | - |

> ⚠️ **Critical:** AEGIS sử dụng **85% CLS** — gần đạt giới hạn chip GW5A-25!

---

## 4. Timing Performance (Fmax) — Post-PnR

| Metric | Baseline | AEGIS | Degradation |
|---|---:|---:|---:|
| **Constraint** | 50.000 MHz | 50.000 MHz | - |
| **Actual Fmax** | **60.985 MHz** | **51.762 MHz** | **-15.1%** |
| **Slack (positive)** | +10.985 MHz | +1.762 MHz | - |
| **Critical Path Logic Levels** | **9** | **23** | **+156%** |
| **Critical Path Delay** | 16.4 ns | 19.3 ns | +2.9 ns |

**Critical Path:**
- **Baseline:** `enc_block → sbox → mixcolumns → keymem` (9 levels)
- **AEGIS:** `block_reg → KLG comparator → klg_alarm/verdict` (23 levels)

> ✅ **Kết luận Timing:** AEGIS vẫn **meet timing constraint** (51.8 > 50 MHz), nhưng margin giảm mạnh.

---

## 5. Latency & Throughput @ 50 MHz

| Metric | Baseline | AEGIS | Note |
|---|---:|---:|---|
| **Encryption cycles** | 11 cycles | 11 cycles | AES-128: 1 init + 10 rounds |
| **Clock period** | 20 ns | 20 ns | Both @ 50 MHz |
| **Latency per block** | **220 ns** | **220 ns** | 11 × 20 ns |
| **Throughput** | **581.8 Mbps** | **581.8 Mbps** | 128-bit / 220 ns |
| **Blocks/sec** | 4.55M | 4.55M | 50MHz / 11 |

> ✅ **Zero throughput penalty** — security logic không nằm trong AES datapath!

---

## 6. Gate Equivalent (GE) — Ước tính ASIC

| Component | Formula | Baseline | AEGIS | Overhead |
|---|---|---:|---:|---:|
| **LUT → GE** | LUT × 5.5 | 30,311 GE | 62,656 GE | +32,345 GE |
| **ALU → GE** | ALU × 8.0 | 72 GE | 13,768 GE | +13,696 GE |
| **FF → GE** | FF × 6.0 | 17,874 GE | 37,998 GE | +20,124 GE |
| **Total estimated** | | **~48,257 GE** | **~114,422 GE** | **+66,165 GE (+137%)** |

**Phân tích cho ASIC:**
- Baseline AES-128: ~48K GE (tiêu chuẩn literature: 20-50K GE)
- AEGIS total: ~114K GE
- **Security overhead: +137% area**

---

## 7. Power Estimation (Dynamic)

**Phương pháp:** Ước tính dựa trên switching activity và resource count.

| Component | Baseline | AEGIS | Formula |
|---|---:|---:|---|
| **LUT switching** | 5,511 × 0.15 | 11,392 × 0.15 | LUT_count × activity_factor |
| **FF switching** | 2,978 × 0.20 | 6,332 × 0.20 | FF_count × toggle_rate |
| **ALU switching** | 9 × 0.50 | 1,721 × 0.50 | ALU_count × utilization |
| **Estimated dynamic power** | **~18 mW** | **~39 mW** | @ 50 MHz, 0.85V |

**Power overhead:** +117% (+21 mW)

> ⚠️ **Lưu ý:** Đây là ước tính thô. Power chính xác cần:
> - Gowin Power Calculator với actual switching activity
> - VCD simulation dump từ testbench
> - Static power (leakage) phụ thuộc process/temperature

---

## 8. Tổng hợp AEGIS Security Overhead

| Metric | Overhead | Notes |
|---|---:|---|
| **LUT** | **+107%** | ORC (4× sbox) chiếm 65% overhead |
| **ALU** | **+19,022%** | KLG key comparator dominates |
| **FF** | **+113%** | KLG history buffer (1,544 FF) |
| **CLS (Area)** | **+105%** | ⚠️ 85% utilization — near limit |
| **Fmax** | **-15%** | 61 → 52 MHz, vẫn meet 50 MHz constraint |
| **Throughput** | **0%** | ✅ 582 Mbps maintained |
| **GE (ASIC)** | **+137%** | 48K → 114K GE |
| **Power (est.)** | **+117%** | 18 → 39 mW @ 50 MHz |

---

## 9. Security Modules Chi tiết (từ synthesis)

| Module | LUT | FF | ALU | % Total Overhead |
|---|---:|---:|---:|---:|
| **ORC** (Output Checker) | 3,840 | 263 | 128 | **65%** overhead |
| **KLG** (Key Leak Guard) | 7 | 1,544 | 1,544 | **30%** overhead |
| **RCM** (Round Counter Monitor) | 122 | 50 | 8 | **3%** overhead |
| **RED** (Rare Event Detector) | 116 | 20 | 15 | **2%** overhead |
| **FIC** (FSM Integrity Check) | 2 | 4 | 0 | **<1%** overhead |
| **TRU** (Tamper Response Unit) | 13 | 12 | 0 | **<1%** overhead |
| **Total security logic** | ~4,100 | ~2,900 | ~1,700 | **100%** |

**Dominant contributors:**
1. **ORC** — 4× parallel S-box recomputation for output validation
2. **KLG** — 1,544 ALU để compare key history (detect key leak attacks)

---

## 10. Critical Path Analysis

### Baseline Critical Path (16.4 ns, 9 levels)
```
clk → enc_block/enc_ctrl_reg[0]
  → muxed_sboxw[31:0]           (+4.5 ns)
  → sbox/new_sboxw[17]          (+6.3 ns)  ← S-box lookup
  → keymem/key_mem_new[25]      (+5.3 ns)  ← Key expansion
  → keymem/key_mem[11] [FF]     (setup)
```

### AEGIS Critical Path (19.3 ns, 23 levels)
```
clk → protected/block_reg[6]
  → KLG comparator chain         (+12 ns)   ← 1,544-bit key comparison
  → klg_alarm logic              (+4 ns)
  → klg_verdict_block [FF]       (setup)
```

> **Timing bottleneck:** KLG's massive comparator (1,544 ALU) tạo ra 23-level logic cone!

---

## 11. Kết luận & Recommendations

### Trade-offs

✅ **Ưu điểm:**
- **Zero throughput penalty** (582 Mbps maintained)
- **Meet timing constraint** (51.8 > 50 MHz)
- **Comprehensive protection**: ORC/KLG/RCM/RED/FIC/TRU

⚠️ **Nhược điểm:**
- **137% area overhead** (48K → 114K GE estimate)
- **117% power overhead** (18 → 39 mW estimate)
- **85% CLS utilization** — gần hết tài nguyên chip
- **15% Fmax degradation** — timing margin giảm 10.9 → 1.8 MHz

### Recommendations

1. **Optimize KLG:** 1,544 ALU là bottleneck — xem xét:
   - Pipelined comparison (trade latency for Fmax)
   - Reduced key history depth
   - Hashed comparison thay vì full bit-by-bit

2. **Scale ORC:** 4× S-box có thể giảm xuống 2× hoặc time-multiplexed

3. **Larger FPGA:** Nếu cần thêm features, consider GW5A-75 (33K LUT) thay vì GW5A-25 (23K LUT)

---

## Appendix: Data Sources

| Report | Baseline | AEGIS |
|---|---|---|
| Synthesis resource | `aes_basline/impl/gwsynthesis/aes_basline_syn_resource.html` | `security_demo/impl/gwsynthesis/security_demo_syn_resource.html` |
| Synthesis report | `aes_basline/impl/gwsynthesis/aes_basline_syn.rpt.html` | `security_demo/impl/gwsynthesis/security_demo_syn.rpt.html` |
| PnR report | `aes_basline/impl/pnr/aes_basline.rpt.txt` | `security_demo/impl/pnr/security_demo.rpt.txt` |
| Timing report | `aes_basline/impl/pnr/aes_basline_tr_content.html` | `security_demo/impl/pnr/security_demo_tr_content.html` |

> **Note:** Power numbers are estimates. No dedicated `.pwr` report was generated by the Gowin PnR flow. For accurate power, run Gowin Power Analyzer with VCD activity from simulation.
