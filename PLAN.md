# Plan: Implement RCM - Round Consistency Monitor

## Context

T03 (Trojan P3 - skip MixColumns round 5) không leak key nên KLG không phát hiện được. Cần RCM để theo dõi round counter và phát hiện bất thường:
- Trojan skip MixColumns → counter có thể dừng sai round
- Counter FSM sai → phát hiện bất thường

## Files cần sửa

1. **`rtl/aegis/rcm_round_consistency_monitor.v`** (NEW) - Module RCM
2. **`rtl/aegis/aes_core_tapped.v`** (MODIFY) - Tap `muxed_round_nr` ra port output
3. **`rtl/aegis/aegis_aes_top.v`** (MODIFY) - Instantiation RCM, kết nối `rcm_alarm`
4. **`rtl/aegis/aegis_defs.vh`** (ADD) - Định nghĩa `AEGIS_ST_RCM` (đã có)

## Chi tiết implementation

### 1. RCM Module (`rcm_round_consistency_monitor.v`)

**Interface:**
```verilog
module rcm_round_consistency_monitor #(
    parameter NUM_ROUNDS = 10  // AES-128: round 0-10
) (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        encdec,       // Phải là encdec=1 (encrypt)
    input  wire        init,         // Bắt đầu key expansion
    input  wire        next,         // Bắt đầu mã hóa
    input  wire        ready,        // Core ready (kết thúc mã hóa)
    input  wire        result_valid, // Kết quả hợp lệ
    input  wire [3:0]  round_nr,     // Round counter từ aes_core
    output reg         rcm_alarm,
    output reg  [3:0]  rcm_code
);
```

**Thuộc tính cần kiểm tra:**

| Check | Logic | RCM Code |
|-------|-------|----------|
| Round tăng đơn điệu | `round_nr == $past(round_nr) \|\| round_nr == $past(round_nr)+1` | 0x1 |
| Round ≤ 10 | `round_nr <= 4'd10` | 0x2 |
| Done chỉ ở round 10 | Khi `result_valid=1`, `round_nr` phải = 10 | 0x3 |
| Reset về 0 sau xong | Sau `result_valid`, round phải về 0 | 0x4 |

**FSM States:**
```
IDLE → (next=1) → COUNTING → (result_valid) → DONE → (next=1) → COUNTING
```

### 2. Tap `muxed_round_nr` từ aes_core_tapped.v

Thêm output port:
```verilog
module aes_core_tapped (
    // ... existing ports ...
    output wire [3 : 0]  muxed_round_nr  // NEW - tap round counter
);
```

Và nối:
```verilog
assign muxed_round_nr = muxed_round_nr;  // Từ internal reg dòng 113
```

### 3. Integration trong aegis_aes_top.v

```verilog
// Add parameter
parameter EN_RCM = 1

// Add wire
wire       rcm_alarm;
wire [3:0] rcm_code;

// Instantiation
rcm_round_consistency_monitor #(
    .NUM_ROUNDS(10)
) u_rcm (
    .clk(clk),
    .rst_n(rst_n),
    .encdec(1'b1),
    .init(core_init),
    .next(core_next),
    .ready(core_ready),
    .result_valid(core_dvalid),
    .round_nr(u_core.muxed_round_nr),  // Tap từ dut
    .rcm_alarm(rcm_alarm),
    .rcm_code(rcm_code)
);

// Connect to TRU
.tru(
    .rcm_alarm(rcm_alarm),  // Thay 1'b0
    // ...
)
```

## Verification

1. **Compile check:** `make compile` hoặc `iverilog`
2. **Simulate T03:** `make CASE=T03_P3_SKIP_MIXCOL security`
3. **Verify RCM phát hiện:** Check `rcm_alarm` = 1 và `rcm_code` != 0
4. **Verify không ảnh hưởng clean code:** Chạy KAT vectors

## Thứ tự thực hiện

1. Thêm `muxed_round_nr` port vào `aes_core_tapped.v`
2. Tạo `rcm_round_consistency_monitor.v`
3. Tích hợp vào `aegis_aes_top.v`
4. Test với T03

## Lưu ý

- RCM chỉ monitor khi `encdec=1` (encrypt mode)
- FSM phải track trạng thái để biết khi nào bắt đầu/xong encryption
- Không cần SVA properties - chỉ cần check đơn giản trong RTL
