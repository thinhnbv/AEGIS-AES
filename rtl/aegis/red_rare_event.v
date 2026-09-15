//---------------------------------------------------------------
// red_rare_event.v
// Rare-Event Detector - Phat hien cac trigger "hiem" trong plaintext
//
// RED giám sát các tín hiệu "hiếm" dựa trên heuristic:
//   T1 - Trigger tổ hợp: Plaintext bằng hằng số đặc biệt
//   T2 - Trigger tuần tự: Chuỗi plaintext theo pattern
//   T3 - Trigger bộ đếm: Counter đạt ngưỡng threshold
//
// Output:
//   red_warning (1-bit) - cảnh báo mềm, đưa TRU vào SUSPECT
//   red_code[7:0] - mã định danh loại rare event
//---------------------------------------------------------------
`default_nettype none
`include "aegis_defs.vh"

module red_rare_event #(
    parameter [15:0] RARE_THRESHOLD = 16'hFFFF  // 2^16 - 1 = 65535
) (
    input  wire clk,
    input  wire rst_n,
    input  wire [127:0] block,           // plaintext input
    input  wire block_valid,            // valid khi có plaintext mới
    output reg  red_warning,
    output reg  [7:0] red_code           // mã loại rare event
);

  // --- Cac hang so cho cac gia tri plaintext hiếm ---
  localparam RARE_ALL_ZEROS = 128'h0000_0000_0000_0000_0000_0000_0000_0000;
  localparam RARE_ALL_ONES  = 128'hFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF;
  localparam RARE_ALT_ZEROS = 128'h5555_5555_5555_5555_5555_5555_5555_5555;  // 0x55...
  localparam RARE_ALT_ONES  = 128'hAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA;  // 0xAA...
  localparam RARE_LOWER_HALF_ZEROS = 128'h0000_0000_0000_0000_FFFF_FFFF_FFFF_FFFF;
  localparam RARE_UPPER_HALF_ZEROS = 128'hFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000;

  // --- Cac ma loi rare event ---
  localparam CODE_T1_ALL_ZEROS       = 8'h01;  // T1: all zeros
  localparam CODE_T1_ALL_ONES        = 8'h02;  // T1: all ones
  localparam CODE_T1_ALT_PATTERN     = 8'h03;  // T1: alternating pattern
  localparam CODE_T1_HALF_PATTERN    = 8'h04;  // T1: half zeros
  localparam CODE_T2_SEQ_PATTERN     = 8'h10;  // T2: sequential pattern
  localparam CODE_T3_THRESHOLD       = 8'h20;  // T3: counter threshold

  // --- FSM states ---
  localparam FSM_IDLE  = 2'd0;
  localparam FSM_SEQ1 = 2'd1;
  localparam FSM_SEQ2 = 2'd2;
  localparam FSM_SEQ3 = 2'd3;

  // --- Internal registers ---
  reg  [15:0] enc_counter;           // Dem so lan ma hoa
  reg  [1:0]  fsm_state;            // FSM cho T2 pattern detection
  reg  [127:0] pt_history [0:2];    // Lưu 3 plaintext truoc
  integer j;

  // --- Wires cho T1 detection ---
  wire t1_all_zeros;
  wire t1_all_ones;
  wire t1_alt_zeros;
  wire t1_alt_ones;
  wire t1_half_zeros_low;
  wire t1_half_zeros_high;

  // --- Wires cho T2 detection ---
  wire t2_incrementing_seq;    // PT[i] = PT[i-1] + 1
  wire t2_decrementing_seq;    // PT[i] = PT[i-1] - 1
  wire t2_repeating_seq;      // PT[i] = PT[i-2]
  wire t2_any_pattern;

  // --- Wire cho T3 detection ---
  wire t3_threshold_reached;

  //==============================================================
  // T1: Combinational Trigger - Detects rare constant values
  //==============================================================
  assign t1_all_zeros = (block == RARE_ALL_ZEROS);
  assign t1_all_ones  = (block == RARE_ALL_ONES);
  assign t1_alt_zeros = (block == RARE_ALT_ZEROS);
  assign t1_alt_ones  = (block == RARE_ALT_ONES);
  assign t1_half_zeros_low  = (block == RARE_LOWER_HALF_ZEROS);
  assign t1_half_zeros_high = (block == RARE_UPPER_HALF_ZEROS);

  //==============================================================
  // T2: Sequential Trigger - Detects plaintext sequence patterns
  //==============================================================
  // Check incrementing sequence: PT[i] == PT[i-1] + 1
  wire [127:0] pt_minus_one;
  wire         pt_overflow;
  assign {pt_overflow, pt_minus_one} = {1'b0, pt_history[0]} - 128'd1;
  assign t2_incrementing_seq = (block == pt_history[0] + 128'd1) && !pt_overflow;

  // Check decrementing sequence: PT[i] == PT[i-1] - 1
  assign t2_decrementing_seq = (block == pt_minus_one);

  // Check repeating sequence: PT[i] == PT[i-2] (every other same)
  assign t2_repeating_seq = (block == pt_history[2]);

  // Any T2 pattern detected
  assign t2_any_pattern = t2_incrementing_seq || t2_decrementing_seq || t2_repeating_seq;

  //==============================================================
  // T3: Counter Trigger - Threshold-based detection
  //==============================================================
  assign t3_threshold_reached = (enc_counter >= RARE_THRESHOLD[15:0]);

  //==============================================================
  // Main detection logic
  //==============================================================
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      // Reset all outputs and internal state
      red_warning  <= 1'b0;
      red_code     <= 8'd0;
      enc_counter <= 16'd0;
      fsm_state   <= FSM_IDLE;

      // Clear history
      for (j = 0; j < 3; j = j + 1) begin
        pt_history[j] <= 128'd0;
      end
    end else begin
      // Default: clear warning, keep counter
      red_warning <= 1'b0;
      red_code    <= 8'd0;

      // Update plaintext history when new block arrives
      if (block_valid) begin
        // Shift history: pt_history[2] <- pt_history[1] <- pt_history[0] <- block
        pt_history[2] <= pt_history[1];
        pt_history[1] <= pt_history[0];
        pt_history[0] <= block;

        // Increment counter on each encryption
        enc_counter <= enc_counter + 16'd1;

        //==============================================================
        // T1: Check for rare constant plaintext values
        //==============================================================
        if (t1_all_zeros) begin
          red_warning <= 1'b1;
          red_code    <= CODE_T1_ALL_ZEROS;
        end else if (t1_all_ones) begin
          red_warning <= 1'b1;
          red_code    <= CODE_T1_ALL_ONES;
        end else if (t1_alt_zeros || t1_alt_ones) begin
          red_warning <= 1'b1;
          red_code    <= CODE_T1_ALT_PATTERN;
        end else if (t1_half_zeros_low || t1_half_zeros_high) begin
          red_warning <= 1'b1;
          red_code    <= CODE_T1_HALF_PATTERN;
        end
        //==============================================================
        // T2: Check for sequential patterns
        //==============================================================
        else if (t2_incrementing_seq) begin
          red_warning <= 1'b1;
          red_code    <= CODE_T2_SEQ_PATTERN;
          fsm_state   <= FSM_SEQ1;
        end else if (t2_decrementing_seq) begin
          red_warning <= 1'b1;
          red_code    <= CODE_T2_SEQ_PATTERN;
          fsm_state   <= FSM_SEQ2;
        end else if (t2_repeating_seq) begin
          red_warning <= 1'b1;
          red_code    <= CODE_T2_SEQ_PATTERN;
          fsm_state   <= FSM_SEQ3;
        end
        //==============================================================
        // T3: Check counter threshold
        //==============================================================
        else if (t3_threshold_reached) begin
          red_warning <= 1'b1;
          red_code    <= CODE_T3_THRESHOLD;
        end else begin
          // Reset FSM on normal input
          fsm_state <= FSM_IDLE;
        end
      end
    end
  end

endmodule
`default_nettype wire
