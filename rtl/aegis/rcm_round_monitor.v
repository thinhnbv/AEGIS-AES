//---------------------------------------------------------------
// rcm_round_monitor.v
// Round Consistency Monitor - Phat hien bat thuong ve round counter
//
// Theo doi round counter trong qua trinh ma hoa AES:
// - Round phai tang don dieu tu 0 den NUM_ROUNDS
// - Khong co round bi skip hay lap lai ngoai le
// - Ket qua chi hop le khi round = NUM_ROUNDS
//---------------------------------------------------------------
`default_nettype none
`include "aegis_defs.vh"

module rcm_round_monitor #(
    parameter NUM_ROUNDS = 10  // AES-128: 11 rounds (0-10)
) (
    input  wire        clk,
    input  wire        rst_n,

    // Control signals
    input  wire        init,         // Bat dau key expansion
    input  wire        next,         // Bat dau ma hoa
    input  wire        ready,        // Core ready

    // Data signals
    input  wire        result_valid, // Ket qua hop le
    input  wire [3:0] round_nr,    // Round counter tu aes_core

    // Outputs
    output reg         rcm_alarm,
    output reg  [3:0]  rcm_code
);

  // FSM states
  localparam RCM_IDLE    = 2'd0;
  localparam RCM_ACTIVE  = 2'd1;
  localparam RCM_DONE    = 2'd2;
  localparam RCM_ERROR   = 2'd3;

  reg [1:0] state;
  reg [1:0] next_state;

  // Round tracking
  reg [3:0] prev_round_nr;
  reg       first_round_seen;
  reg       saw_result_valid;

  // Track the round when done signal was seen
  reg [3:0] final_round_seen;

  // Track when we first see the final round (NUM_ROUNDS)
  // round_nr jumps from NUM_ROUNDS to NUM_ROUNDS+1 when done
  reg       saw_final_round;

  // Error flags
  wire      round_non_monotonic;
  wire      round_exceeded_max;
  wire      done_not_at_final;
  wire      round_jumped;

  // FSM state transitions
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state <= RCM_IDLE;
      saw_final_round <= 1'b0;
    end else begin
      state <= next_state;
      // Track when we see final round
      if (next)
        saw_final_round <= 1'b0;
      else if (round_nr >= NUM_ROUNDS)
        saw_final_round <= 1'b1;
    end
  end

  always @(*) begin
    next_state = state;

    case (state)
      RCM_IDLE: begin
        if (next)
          next_state = RCM_ACTIVE;
      end

      RCM_ACTIVE: begin
        if (result_valid)
          next_state = RCM_DONE;
        else if (round_non_monotonic || round_exceeded_max || round_jumped)
          next_state = RCM_ERROR;
      end

      RCM_DONE: begin
        if (next)
          next_state = RCM_ACTIVE;
        else if (init)
          next_state = RCM_IDLE;
      end

      RCM_ERROR: begin
        // Sticky - chi thoat bang reset
      end

      default: next_state = RCM_IDLE;
    endcase
  end

  // Round comparison logic
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      prev_round_nr     <= 4'd0;
      first_round_seen <= 1'b0;
      saw_result_valid <= 1'b0;
      final_round_seen <= 4'd0;
    end else begin
      case (state)
        RCM_IDLE: begin
          if (next) begin
            first_round_seen <= 1'b1;
            prev_round_nr    <= round_nr;  // Capture first round
            saw_result_valid <= 1'b0;
            final_round_seen <= 4'd0;
          end
        end

        RCM_ACTIVE: begin
          // Track first round seen
          if (!first_round_seen && round_nr != 4'd0) begin
            first_round_seen <= 1'b1;
            prev_round_nr    <= round_nr;
          end else if (first_round_seen) begin
            prev_round_nr <= round_nr;
          end

          // Track when result becomes valid - capture round number
          if (result_valid) begin
            saw_result_valid <= 1'b1;
            final_round_seen <= round_nr;
          end
        end

        RCM_DONE: begin
          if (next) begin
            first_round_seen <= 1'b0;
            saw_result_valid <= 1'b0;
            final_round_seen <= 4'd0;
          end
        end
      endcase
    end
  end

  // Error detection
  // Chỉ check errors khi đang track encryption (first_round_seen=1)
  assign round_non_monotonic =
    first_round_seen &&
    (round_nr != prev_round_nr) &&
    (round_nr != (prev_round_nr + 4'd1));

  // Chỉ check exceeded khi đang track - round_nr tăng lên NUM_ROUNDS+1 khi hoàn thành
  assign round_exceeded_max =
    first_round_seen && (round_nr > NUM_ROUNDS);

  assign round_jumped =
    first_round_seen &&
    (round_nr > (prev_round_nr + 4'd1));

  // Check final round seen when result was valid
  // round_nr tăng lên NUM_ROUNDS+1 khi hoàn thành, nên chấp nhận cả NUM_ROUNDS và NUM_ROUNDS+1
  assign done_not_at_final =
    saw_result_valid &&
    (final_round_seen < NUM_ROUNDS);

  // Alarm logic
  // Chỉ set alarm khi đang ở ACTIVE và chưa hoàn thành (result_valid chưa set)
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      rcm_alarm <= 1'b0;
      rcm_code  <= 4'd0;
    end else begin
      case (state)
        RCM_ACTIVE: begin
          // Chỉ alarm nếu round vượt trước khi hoàn thành
          // round_nr=NUM_ROUNDS+1 là bình thường khi hoàn thành (saw_final_round=1)
          if (round_non_monotonic) begin
            rcm_alarm <= 1'b1;
            rcm_code  <= 4'd1;  // Round khong tang don dieu
          end else if (round_exceeded_max && !saw_final_round) begin
            // round_nr > NUM_ROUNDS là bất thường CHỈ khi chưa thấy final round
            rcm_alarm <= 1'b1;
            rcm_code  <= 4'd2;  // Round vuot qua gioi han
          end else if (round_jumped) begin
            rcm_alarm <= 1'b1;
            rcm_code  <= 4'd3;  // Round nhay co tach
          end
        end

        RCM_DONE: begin
          if (done_not_at_final) begin
            rcm_alarm <= 1'b1;
            rcm_code  <= 4'd4;  // Ket qua khong o round cuoi
          end
        end

        RCM_ERROR: begin
          // Sticky alarm - giu nguyen
        end
      endcase
    end
  end

endmodule
`default_nettype wire
