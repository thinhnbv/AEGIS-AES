//---------------------------------------------------------------
// orc_output_checker.v
// Output Redundancy Checker - Phat hien bat thuong o round cuoi
//
// ORC nhan ban duong tinh round cuoi (SubBytes-ShiftRows-AddRoundKey)
// va so sanh voi ket qua tu duong chinh. Sai khac 1 bit se bi bat.
//
// Chong lai: P2 (slow leak), P3 (skip MixColumns, bypass round)
//---------------------------------------------------------------
`default_nettype none
`include "aegis_defs.vh"

module orc_output_checker #(
    parameter NUM_ROUNDS = 10  // AES-128: 11 rounds (0-10)
) (
    input  wire        clk,
    input  wire        rst_n,

    // Encryption control
    input  wire        next,           // Bat dau ma hoa
    input  wire        result_valid,   // Ket qua hop le
    input  wire [3:0] round_nr,       // Round counter tu aes_core

    // Tapped state before final round (from aes_encipher_block)
    input  wire [127:0] state_before_final,

    // Final round key (from key memory)
    input  wire [127:0] final_round_key,

    // Core output
    input  wire [127:0] core_result,

    // ORC output
    output reg          orc_alarm,
    output reg  [3:0]  orc_code
);

  // FSM states
  localparam ORC_IDLE   = 2'd0;
  localparam ORC_ACTIVE = 2'd1;
  localparam ORC_CHECK  = 2'd2;
  localparam ORC_ERROR  = 2'd3;

  reg [1:0] state;
  reg [1:0] next_state;

  // Captured signals for verification
  reg [127:0] captured_input;
  reg [127:0] captured_key;
  reg         has_captured;

  // Computed final round result
  wire [127:0] computed_final;

  // SubBytes signals
  wire [31:0] sboxw_w0, sboxw_w1, sboxw_w2, sboxw_w3;
  wire [31:0] new_sboxw_w0, new_sboxw_w1, new_sboxw_w2, new_sboxw_w3;

  // State after SubBytes (before ShiftRows)
  wire [127:0] after_subbytes;

  // ShiftRows wires
  wire [127:0] after_shiftrows;

  // Mismatch detection
  wire mismatch;

  // Instantiate 4 S-boxes for parallel SubBytes (one per 32-bit word)
  aes_sbox sbox_w0 (.sboxw(sboxw_w0), .new_sboxw(new_sboxw_w0));
  aes_sbox sbox_w1 (.sboxw(sboxw_w1), .new_sboxw(new_sboxw_w1));
  aes_sbox sbox_w2 (.sboxw(sboxw_w2), .new_sboxw(new_sboxw_w2));
  aes_sbox sbox_w3 (.sboxw(sboxw_w3), .new_sboxw(new_sboxw_w3));

  // SubBytes: apply S-box to each byte
  // State format: [w0_msb..w0_lsb, w1_msb..w1_lsb, w2_msb..w2_lsb, w3_msb..w3_lsb]
  // Each word is 4 bytes in column-major order
  assign sboxw_w0 = captured_input[127:96];
  assign sboxw_w1 = captured_input[95:64];
  assign sboxw_w2 = captured_input[63:32];
  assign sboxw_w3 = captured_input[31:0];

  // After SubBytes, reconstruct the state
  // AES SubBytes operates byte-by-byte, so each S-box output replaces its input byte
  assign after_subbytes[127:120] = new_sboxw_w0[31:24];  // byte 0
  assign after_subbytes[119:112] = new_sboxw_w0[23:16];  // byte 1
  assign after_subbytes[111:104] = new_sboxw_w0[15:8];   // byte 2
  assign after_subbytes[103:96]  = new_sboxw_w0[7:0];    // byte 3
  assign after_subbytes[95:88]   = new_sboxw_w1[31:24];  // byte 4
  assign after_subbytes[87:80]   = new_sboxw_w1[23:16];  // byte 5
  assign after_subbytes[79:72]   = new_sboxw_w1[15:8];   // byte 6
  assign after_subbytes[71:64]   = new_sboxw_w1[7:0];    // byte 7
  assign after_subbytes[63:56]   = new_sboxw_w2[31:24];  // byte 8
  assign after_subbytes[55:48]   = new_sboxw_w2[23:16];  // byte 9
  assign after_subbytes[47:40]   = new_sboxw_w2[15:8];   // byte 10
  assign after_subbytes[39:32]   = new_sboxw_w2[7:0];    // byte 11
  assign after_subbytes[31:24]   = new_sboxw_w3[31:24];  // byte 12
  assign after_subbytes[23:16]   = new_sboxw_w3[23:16];  // byte 13
  assign after_subbytes[15:8]    = new_sboxw_w3[15:8];   // byte 14
  assign after_subbytes[7:0]     = new_sboxw_w3[7:0];    // byte 15

  // ShiftRows: byte-level permutation
  // Row 0: no shift (bytes 0,1,2,3 -> same positions)
  // Row 1: shift left by 1 (bytes 4,5,6,7 -> positions 5,6,7,4)
  // Row 2: shift left by 2 (bytes 8,9,10,11 -> positions 10,11,8,9)
  // Row 3: shift left by 3 (bytes 12,13,14,15 -> positions 15,12,13,14)
  assign after_shiftrows[127:120] = after_subbytes[127:120];  // w0[31:24] -> byte 0 (Row 0)
  assign after_shiftrows[119:112] = after_subbytes[95:88];   // w1[31:24] -> byte 1 (Row 1, shift 1)
  assign after_shiftrows[111:104] = after_subbytes[63:56];   // w2[31:24] -> byte 2 (Row 2, shift 2)
  assign after_shiftrows[103:96]  = after_subbytes[31:24];   // w3[31:24] -> byte 3 (Row 3, shift 3)
  assign after_shiftrows[95:88]   = after_subbytes[87:80];   // w1[23:16] -> byte 4 (Row 1)
  assign after_shiftrows[87:80]   = after_subbytes[79:72];   // w1[15:8] -> byte 5 (Row 1)
  assign after_shiftrows[79:72]   = after_subbytes[71:64];   // w1[7:0] -> byte 6 (Row 1)
  assign after_shiftrows[71:64]   = after_subbytes[119:112]; // w0[7:0] -> byte 7 (Row 1, wrap)
  assign after_shiftrows[63:56]   = after_subbytes[47:40];   // w2[15:8] -> byte 8 (Row 2, shift 2)
  assign after_shiftrows[55:48]   = after_subbytes[39:32];   // w2[7:0] -> byte 9 (Row 2)
  assign after_shiftrows[47:40]   = after_subbytes[127:120]; // w0[31:24] -> byte 10 (Row 2, wrap)
  assign after_shiftrows[39:32]   = after_subbytes[95:88];   // w1[31:24] -> byte 11 (Row 2, wrap)
  assign after_shiftrows[31:24]   = after_subbytes[7:0];     // w3[7:0] -> byte 12 (Row 3, shift 3)
  assign after_shiftrows[23:16]   = after_subbytes[127:120]; // w0[31:24] -> byte 13 (Row 3, wrap)
  assign after_shiftrows[15:8]    = after_subbytes[119:112]; // w0[23:16] -> byte 14 (Row 3, wrap)
  assign after_shiftrows[7:0]     = after_subbytes[111:104]; // w0[15:8] -> byte 15 (Row 3, wrap)

  // AddRoundKey: XOR with final round key
  assign computed_final = after_shiftrows ^ captured_key;

  // Compare with core output
  assign mismatch = (computed_final != core_result);

  // FSM state transition
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state <= ORC_IDLE;
    end else begin
      state <= next_state;
    end
  end

  always @(*) begin
    next_state = state;

    case (state)
      ORC_IDLE: begin
        if (next) begin
          next_state = ORC_ACTIVE;
        end
      end

      ORC_ACTIVE: begin
        // Wait for encryption to complete
        if (result_valid) begin
          next_state = ORC_CHECK;
        end
      end

      ORC_CHECK: begin
        if (next) begin
          next_state = ORC_ACTIVE;
        end else if (mismatch) begin
          next_state = ORC_ERROR;
        end else begin
          next_state = ORC_IDLE;
        end
      end

      ORC_ERROR: begin
        // Sticky - chi thoat bang reset
      end

      default: next_state = ORC_IDLE;
    endcase
  end

  // Capture input state and key when entering final round
  // When round_nr == NUM_ROUNDS (10), block registers hold state BEFORE final round
  reg [3:0] prev_round_nr;

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      prev_round_nr    <= 4'd0;
      captured_input  <= 128'd0;
      captured_key   <= 128'd0;
      has_captured  <= 1'b0;
    end else begin
      prev_round_nr <= round_nr;

      // Clear on new encryption start
      if (next) begin
        has_captured   <= 1'b0;
        captured_input <= 128'd0;
        captured_key  <= 128'd0;
      end

      // Capture when entering final round (round_nr == NUM_ROUNDS = 10)
      // At this point, block registers hold state BEFORE final round executes
      if (round_nr == NUM_ROUNDS) begin
        captured_input  <= state_before_final;
        captured_key   <= final_round_key;
        has_captured  <= 1'b1;
      end
    end
  end

  // Alarm logic - only fire in ERROR state (after manual confirmation)
  // For now, don't fire alarm automatically to debug
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      orc_alarm <= 1'b0;
      orc_code  <= 4'd0;
    end else begin
      case (state)
        ORC_ERROR: begin
          // Sticky alarm - giu nguyen
          orc_alarm <= 1'b1;
        end

        default: begin
          // No change - don't fire alarm automatically during CHECK
        end
      endcase
    end
  end

endmodule
`default_nettype wire
