# AEGIS-AES Architecture Overview

## 1. System Overview

AEGIS-AES là một hệ thống mã hóa AES-128 được thiết kế với khả năng **chống lại Trojan phần cứng (Hardware Trojan)**. Hệ thống bao gồm:

- **Core AES-128** với các điểm tap tín hiệu để giám sát
- **5 module phát hiện Trojan** hoạt động đồng thời
- **Tamper Response Unit (TRU)** để phản ứng khi phát hiện Trojan
- **5 biến thể Trojan** để test và đánh giá

---

## 2. Block Diagram cấp cao

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              aegis_aes_top                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Wrapper FSM                                   │   │
│  │   IDLE → WAIT_KEY_BUSY → WAIT_KEY_DONE → READY                     │   │
│  │                           ↓                                          │   │
│  │                      WAIT_RESULT_LOW → WAIT_RESULT_HIGH             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌───────────────────┐         ┌──────────────────────────────────────┐   │
│  │   AES Core        │◄────────│  Round Keys (11 x 128-bit)            │   │
│  │   (aes_core_tapped)│       │  Round Counter                        │   │
│  │                   │        │  State Before Final Round             │   │
│  └─────────┬─────────┘        └──────────────────────────────────────┘   │
│            │                                                         ▲     │
│            │ data_out[127:0]                                          │     │
│            ▼                                                         │     │
│  ┌─────────────────────────────────────────────────────────────────┐ │     │
│  │                     TROJAN DETECTORS                              │ │     │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐     │ │     │
│  │  │   KLG   │ │   FIC   │ │   RCM   │ │   ORC   │ │   RED   │     │ │     │
│  │  │ Key Le- │ │  FSM    │ │ Round   │ │Output   │ │  Rare   │     │ │     │
│  │  │   ak    │ │Integrity│ │Consist. │ │Redund.  │ │  Event  │     │ │     │
│  │  │ Guard   │ │ Checker │ │Monitor  │ │Checker  │ │Detector │     │ │     │
│  │  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘     │ │     │
│  │       │           │           │           │           │           │ │     │
│  │       ▼           ▼           ▼           ▼           ▼           │ │     │
│  │  ┌─────────────────────────────────────────────────────────┐      │ │     │
│  │  │              tru_tamper_response (TRU)                 │      │ │     │
│  │  │         FSM: NORMAL → SUSPECT → LOCKDOWN               │      │ │     │
│  │  └─────────────────────────────────────────────────────────┘      │ │     │
│  └─────────────────────────────────────────────────────────────────┘ │     │
│                                      │                                     │     │
│                                      ▼                                     │     │
│  ┌─────────────────────────────────────────────────────────────────┐ │     │
│  │                          OUTPUT                                  │ │     │
│  │              data_out, data_out_valid, sec_alarm                │ │     │
│  └─────────────────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Module Hierarchy

```
rtl/
├── aegis/                           # AEGIS Secure AES Core
│   ├── aegis_aes_top.v              # ⭐ Top-level wrapper (FSM + integration)
│   ├── aegis_defs.vh                # Constants and state definitions
│   │
│   ├── aes_core_tapped.v            # AES-128 core với tap signals
│   │   ├── aes_key_mem_tapped.v     # Key memory với round key outputs
│   │   └── aes_encipher_block.v     # Encryption datapath
│   │       └── aes_sbox.v           # S-box lookup table
│   │
│   ├── [TROJAN DETECTORS]           # 5 Detector modules
│   │   ├── klg_key_leak_guard.v     # Detects: T01 (key dump), T02 (slow leak)
│   │   ├── fic_fsm_integrity.v     # Detects: T04 (FSM corruption)
│   │   ├── rcm_round_monitor.v      # Detects: T03 (round skip), T05 (DoS)
│   │   ├── orc_output_checker.v      # Detects: T02 (slow leak), T03 (skip MixCol)
│   │   └── red_rare_event.v         # Detects: T01-T05 trigger patterns
│   │
│   └── tru_tamper_response.v        # Tamper Response Unit (TRU)
│
├── aes_golden/                      # Reference AES implementation
│   ├── aes_core.v                   # Original secworks/aes
│   ├── aes_key_mem.v
│   ├── aes_encipher_block.v
│   ├── aes_decipher_block.v
│   └── aes_sbox.v
│
└── infected/                        # Trojan-infected variants
    ├── T01_p1_key_dump/             # Trojan T01: Key Dump
    │   ├── aes_core.v               # Leaks key via data_out
    │   └── aes_core_tapped.v
    │
    ├── T02_p2_slow_leak/            # Trojan T02: Slow Key Leak
    │   ├── aes_core.v
    │   └── aes_core_tapped.v
    │
    ├── T03_p3_skip_mixcol/          # Trojan T03: Skip MixColumns
    │   ├── aes_core.v
    │   └── aes_core_tapped.v
    │
    ├── T04_p4_debug_port/            # Trojan T04: Debug Port
    │   ├── aes_core.v               # FSM illegal state injection
    │   └── aes_core_tapped.v
    │
    └── T05_dos_trojan/              # Trojan T05: DoS Trojan
        ├── aes_core.v               # Locks up encryption
        └── aes_core_tapped.v
```

---

## 4. Chi tiết các Block lớn

### 4.1 Wrapper FSM (aegis_aes_top)

**Chức năng**: Quản lý protocol đơn giản, chuyển đổi sang giao thức của secworks/aes core.

```
States:
┌────────┐    key_valid    ┌──────────────────┐   ~core_ready   ┌────────────────┐
│ IDLE   │────────────────►│ WAIT_KEY_BUSY    │────────────────►│ WAIT_KEY_DONE  │
└────────┘                 └──────────────────┘                 └───────┬────────┘
     ▲                                                               │ core_ready
     │                                                               ▼
     │                                                       ┌───────────────┐
     │                                                       │    READY      │
     │                                                       └───────┬───────┘
     │                                                               │
     │                               data_in_valid                   │
     │                              ┌──────────────────────┐        │
     │                              ▼                      │        │
     │                    ┌─────────────────────┐          │        │
     │                    │ WAIT_RESULT_LOW     │          │        │
     │                    └──────────┬──────────┘          │        │
     │                               │ core_dvalid         │        │
     │                               ▼                     │        │
     │                    ┌─────────────────────┐         │        │
     │                    │ WAIT_RESULT_HIGH    │◄────────┘        │
     │                    └─────────────────────┘    key_valid     │
     └──────────────────────────────────────────────────────────────┘
```

**Interface**:
| Signal | Direction | Description |
|--------|-----------|-------------|
| `key[127:0]` | Input | AES-128 key |
| `key_valid` | Input | Key load trigger |
| `data_in[127:0]` | Input | Plaintext block |
| `data_in_valid` | Input | Encryption trigger |
| `data_out[127:0]` | Output | Ciphertext |
| `data_out_valid` | Output | Output valid pulse |
| `busy` | Output | Core busy flag |
| `sec_alarm` | Output | Hard alarm (Trojan detected) |
| `sec_warning` | Output | Soft warning (rare event) |
| `sec_status[7:0]` | Output | Status bitmap |

---

### 4.2 AES Core (aes_core_tapped)

**Chức năng**: AES-128 encryption engine với các tap signals cho detector.

**Architecture**:
```
aes_core_tapped
├── aes_key_mem_tapped          # Key expansion, outputs 11 round keys
├── aes_encipher_block          # 10-round encryption datapath
│   ├── SubBytes (16 x S-box)
│   ├── ShiftRows
│   ├── MixColumns
│   └── AddRoundKey
└── Control FSM (3 states)
    ├── CTRL_IDLE = 2'b00
    ├── CTRL_INIT = 2'b01
    └── CTRL_NEXT = 2'b10
```

**Tap Signals** (output):
- `round_keys_flat[1407:0]` - 11 round keys concatenated
- `muxed_round_nr[3:0]` - Current round counter
- `state_before_final[127:0]` - State before final round
- `aes_core_ctrl_reg[1:0]` - FSM state (for FIC)

---

### 4.3 Trojan Detectors (5 modules)

#### 4.3.1 KLG - Key Leak Guard

**Mục tiêu**: Phát hiện khóa AES xuất hiện trên đường dữ liệu.

**Detection Layers**:
```
┌────────────────────────────────────────────────────────────┐
│                     KLG Architecture                        │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  data_out[127:0]                                          │
│       │                                                    │
│       ├──────────────────────────────────────────────────┐  │
│       │ Layer 1: Full 128-bit Match                     │  │
│       │  ┌─────────────────┐    ┌───────────────────┐   │  │
│       │  │ Match key_reg?  │    │ Match round_keys? │   │  │
│       │  └────────┬────────┘    └─────────┬─────────┘   │  │
│       │           │                       │              │  │
│       └───────────┼───────────────────────┘              │  │
│                   ▼                                      │  │
│       ┌─────────────────────────────────────────────────┐│  │
│       │ Layer 2: 32-bit Lane Match                     ││  │
│       │  Check each 32-bit word against key_reg        ││  │
│       └─────────────────────────────────────────────────┘│  │
│                   │                                      │  │
│                   ▼                                      │  │
│       ┌─────────────────────────────────────────────────┐│  │
│       │ Layer 3: Hamming Distance                      ││  │
│       │  Alarm if distance < 16 bits to key           ││  │
│       └─────────────────────────────────────────────────┘│  │
│                   │                                      │  │
│                   ▼                                      │  │
│              klg_alarm                                   │  │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

**Trojans detected**: T01 (key dump), T02 (slow key leak)

**Output codes**:
| Code | Meaning |
|------|---------|
| 4'b0001 | Full key or round key match |
| 4'b0010 | Single 32-bit lane match |
| 4'b0011 | Hamming distance < 16 |

---

#### 4.3.2 FIC - FSM Integrity Checker

**Mục tiêu**: Phát hiện bất thường trong FSM của AES core.

**Checks**:
1. **One-hot check**: FSM chỉ có giá trị `00`, `01`, `10`. Giá trị `11` là illegal.
2. **Transition validation**: Chỉ chấp nhận các transition hợp lệ.

```
Valid FSM Transitions:
─────────────────────────────────────────────────
From State     │ Valid Next States
─────────────────────────────────────────────────
CTRL_IDLE (0)  │ CTRL_IDLE, CTRL_INIT, CTRL_NEXT
CTRL_INIT (1)  │ CTRL_IDLE, CTRL_INIT
CTRL_NEXT (2)  │ CTRL_IDLE, CTRL_NEXT
─────────────────────────────────────────────────
```

**Trojans detected**: T04 (debug port - FSM illegal state injection)

---

#### 4.3.3 RCM - Round Consistency Monitor

**Mục tiêu**: Theo dõi round counter để phát hiện round skip hoặc manipulation.

```
┌─────────────────────────────────────────────────────────┐
│                   Round Counter Behavior                 │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Round counter phải tăng đơn điệu:                     │
│                                                          │
│  0 → 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11      │
│  │                                                          │
│  │── Start ──────────────────── End ────│                  │
│                                            │               │
│  result_valid asserted when round = 11    │               │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

**Error conditions**:
| Condition | Code | Meaning |
|-----------|------|---------|
| Non-monotonic | 4'b0001 | Round counter không tăng đơn điệu |
| Exceeded max | 4'b0010 | Round vượt quá 11 |
| Jumped | 4'b0011 | Round nhảy có tính |

**Trojans detected**: T03 (skip MixColumns), T05 (DoS)

---

#### 4.3.4 ORC - Output Redundancy Checker

**Mục tiêu**: Xác minh round cuối bằng cách tính toán độc lập.

```
┌─────────────────────────────────────────────────────────────┐
│                    ORC Architecture                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────┐    state_before_final    ┌─────────────┐ │
│  │   Capture   │◄──────────────────────────│ aes_core    │ │
│  │   Input     │                           │ (tap)       │ │
│  └──────┬──────┘                           └──────┬──────┘ │
│         │                                         │        │
│         │ final_round_key                         │        │
│         │ ◄───────────────────────────────────────┘        │
│         │                                                   │
│         ▼                                                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │          Independent Final Round Calculation        │   │
│  │                                                     │   │
│  │  1. SubBytes (S-box lookup)                        │   │
│  │  2. ShiftRows                                      │   │
│  │  3. AddRoundKey (XOR with final_round_key)        │   │
│  │                                                     │   │
│  └──────────────────────┬──────────────────────────────┘   │
│                         │                                   │
│                         ▼                                   │
│                  ┌─────────────┐                            │
│                  │  Comparator │                            │
│                  └──────┬──────┘                            │
│                         │ mismatch                           │
│                         ▼                                   │
│                    orc_alarm                                │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Trojans detected**: T02 (slow leak), T03 (skip MixColumns)

---

#### 4.3.5 RED - Rare Event Detector

**Mục tiêu**: Phát hiện plaintext trigger patterns.

```
┌────────────────────────────────────────────────────────────────┐
│                    RED Trigger Detection                        │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  plaintext[127:0]                                              │
│       │                                                         │
│       ├──────────────────────────────────────────────────────┐  │
│       │ T1: Constant Triggers (Combinational)               │  │
│       │                                                      │  │
│       │  • All zeros       → 0x0000...0000                   │  │
│       │  • All ones        → 0xFFFF...FFFF                   │  │
│       │  • Alternating     → 0x5555...5555, 0xAAAA...AAAA    │  │
│       │  • Half patterns   → 0x0000...FFFF                   │  │
│       └──────────────────────────────────────────────────────┘  │
│       │                                                         │
│       ├──────────────────────────────────────────────────────┐  │
│       │ T2: Sequential Triggers (History-based)             │  │
│       │                                                      │  │
│       │  • Incrementing   → PT[i] = PT[i-1] + 1              │  │
│       │  • Decrementing   → PT[i] = PT[i-1] - 1              │  │
│       │  • Repeating      → PT[i] = PT[i-2]                  │  │
│       └──────────────────────────────────────────────────────┘  │
│       │                                                         │
│       ├──────────────────────────────────────────────────────┐  │
│       │ T3: Counter Trigger (Threshold)                      │  │
│       │                                                      │  │
│       │  • enc_counter >= 0xFFFF (65535)                     │  │
│       └──────────────────────────────────────────────────────┘  │
│       │                                                         │
│       ▼                                                         │
│  red_warning + red_code                                         │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

**Trojans detected**: T01-T05 (all, via trigger detection)

---

### 4.4 TRU - Tamper Response Unit

**Chức năng**: Phản ứng với các cảnh báo từ detectors.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           TRU State Machine                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│                           ┌──────────────┐                               │
│                           │    NORMAL   │◄──────────────────┐          │
│                           └──────┬───────┘                   │          │
│                                  │                           │          │
│                    red_warning   │   hard_alarm              │          │
│                    (soft alarm)  │   (KLG/FIC/RCM/ORC)       │          │
│                                  │                           │          │
│                                  ▼                           │          │
│                           ┌──────────────┐                   │          │
│                           │   SUSPECT    │───────────────────┤          │
│                           └──────┬───────┘                   │          │
│                                  │                           │          │
│              red_warning x 3     │   hard_alarm              │          │
│              (warn_cnt >= 4)     │                           │          │
│                                  ▼                           ▼          │
│                           ┌──────────────────────────────────────┐      │
│                           │            LOCKDOWN                   │      │
│                           │  • sec_alarm = 1                     │      │
│                           │  • zeroize = 1 (clear all keys)    │      │
│                           │  • block_output = 1 (block output)  │      │
│                           └──────────────────────────────────────┘      │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**Actions in LOCKDOWN**:
1. `sec_alarm = 1` - Báo động cứng
2. `zeroize = 1` - Xóa toàn bộ key schedule (reset AES core)
3. `block_output = 1` - Chặn output, trả về zeros

**Status bits** (sec_status[7:0]):
| Bit | Detector | Meaning |
|-----|----------|---------|
| 0 | KLG | Key leak detected |
| 1 | FIC | FSM integrity violation |
| 2 | RCM | Round counter anomaly |
| 3 | RED | Rare event detected |
| 4 | ORC | Output mismatch |

---

## 5. Trojan Variants

| ID | Name | Type | Mechanism | Detected By |
|----|------|------|-----------|-------------|
| T01 | Key Dump | Exfiltration | Output key on special trigger | KLG, RED |
| T02 | Slow Leak | Exfiltration | Leaky data over many cycles | KLG, ORC |
| T03 | Skip MixColumns | Behavior Mod | Skip MixColumns in round 9 | RCM, ORC |
| T04 | Debug Port | Exfiltration | FSM illegal state + key leak | FIC, KLG |
| T05 | DoS Trojan | Denial of Service | Lock up core during encryption | RCM |

---

## 6. Verification Architecture

```
verif/
├── tb/
│   ├── tb_security.sv              # ⭐ Main security testbench
│   │   └── Tests all 5 Trojans
│   │   └── Verifies all 5 detectors
│   │   └── Measures detection latency
│   │
│   ├── tb_aegis_top.sv            # Functional verification
│   ├── tb_aes_golden.sv           # Reference model comparison
│   └── tb_t05_dos.sv              # DoS-specific test
│
└── tb_golden/                     # Golden model tests
    ├── tb_aes.v
    ├── tb_aes_core.v
    └── ...
```

---

## 7. Data Flow Summary

```
┌──────────────────────────────────────────────────────────────────────────┐
│                              Encryption Flow                              │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  1. Load Key                                                              │
│     key + key_valid → [aegis_aes_top] → [aes_core_tapped]                 │
│                      → Key expansion → round_keys_flat                     │
│                                                                           │
│  2. Encryption                                                            │
│     data_in + data_in_valid → [aegis_aes_top FSM]                        │
│                              → core_next pulse                            │
│                              → [aes_core_tapped]                          │
│                              → 10 rounds (0-9)                            │
│                              → round 10 (final, no MixColumns)           │
│                              → data_out ready                            │
│                                                                           │
│  3. Detection (parallel with encryption)                                  │
│     data_out ──┬──► KLG ──► klg_alarm ──┐                                │
│                ├──► FIC ──► fic_alarm ──┤                                │
│                ├──► RCM ──► rcm_alarm ──┼──► TRU ──► sec_alarm           │
│                ├──► ORC ──► orc_alarm ──┤         └─► zeroize             │
│                └──► RED ──► red_warning─┘         └─► block_output       │
│                                                                           │
│  4. Output Gating                                                         │
│     TRU verdict ──► block_output ──► [AND gate] ──► data_out (final)     │
│                                                                           │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 8. FPGA Demo Architecture

```
fpga/
├── gowin/aegis_demo/              # Gowin FPGA implementation
│   └── src/
│       ├── top_demo.v             # Top-level with UART command
│       ├── uart_cmd_fsm.v         # Command parser
│       ├── aes_key_mem_tapped.v
│       ├── aes_core_tapped.v
│       └── aes_encipher_block.v
│
├── host/
│   ├── demo_cli.py               # Python CLI interface
│   └── test_uart.py              # UART test script
│
└── uart/                         # UART components
    ├── uart_rx.v
    └── uart_tx.v
```

**UART Commands**:
| Command | Description |
|---------|-------------|
| `K` + 16 bytes | Load 128-bit key |
| `D` + 16 bytes | Encrypt data block |
| `S` | Get security status |
| `R` | Reset |

---

## 9. Build Structure

```
Makefile targets:
├── verif          # Run security testbench (all Trojans)
├── verif_t01     # Run T01 specific test
├── verif_t02     # Run T02 specific test
├── verif_t03     # Run T03 specific test
├── verif_t04     # Run T04 specific test
├── verif_t05     # Run T05 specific test
├── fpga          # Build FPGA bitstream
└── clean         # Clean build artifacts
```

---

*Document generated: Architecture Overview for AEGIS-AES Trojan-Hardened Cryptographic Core*
