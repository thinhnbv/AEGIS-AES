//---------------------------------------------------------------
// red_rare_event.v
//
// Rare-Event Detector (RED)
//
// RED observes rare plaintext conditions and produces a ONE-CYCLE
// warning pulse. red_code is sticky and records the latest detected
// rare-event class.
//
// Supported events:
//   T1: rare constant plaintext patterns.
//   T2: benchmark sequence A5 -> 5A -> FF on block[127:120].
//   T3: encryption counter reaches RARE_THRESHOLD.
//
// RED is a soft-warning monitor. A single red_warning must not be
// counted repeatedly by TRU on subsequent clock cycles.
//---------------------------------------------------------------

`default_nettype none
`include "aegis_defs.vh"

module red_rare_event #(
    parameter [15:0] RARE_THRESHOLD = 16'hFFFF
) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire [127:0] block,
    input  wire         block_valid,

    output reg          red_warning,
    output reg  [7:0]   red_code
);

  //-------------------------------------------------------------
  // T1 rare constants.
  //-------------------------------------------------------------
  localparam [127:0] RARE_ALL_ZEROS =
      128'h0000_0000_0000_0000_0000_0000_0000_0000;

  localparam [127:0] RARE_ALL_ONES =
      128'hFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF;

  localparam [127:0] RARE_ALT_ZEROS =
      128'h5555_5555_5555_5555_5555_5555_5555_5555;

  localparam [127:0] RARE_ALT_ONES =
      128'hAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA;

  localparam [127:0] RARE_LOWER_HALF_ZEROS =
      128'h0000_0000_0000_0000_FFFF_FFFF_FFFF_FFFF;

  localparam [127:0] RARE_UPPER_HALF_ZEROS =
      128'hFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000;


  //-------------------------------------------------------------
  // RED codes.
  //-------------------------------------------------------------
  localparam [7:0] CODE_T1_ALL_ZEROS    = 8'h01;
  localparam [7:0] CODE_T1_ALL_ONES     = 8'h02;
  localparam [7:0] CODE_T1_ALT_PATTERN  = 8'h03;
  localparam [7:0] CODE_T1_HALF_PATTERN = 8'h04;

  localparam [7:0] CODE_T2_SEQ_PATTERN  = 8'h10;
  localparam [7:0] CODE_T3_THRESHOLD    = 8'h20;


  //-------------------------------------------------------------
  // T2 sequence state:
  //
  //   WAIT_A5 --A5--> WAIT_5A
  //   WAIT_5A --5A--> WAIT_FF
  //   WAIT_FF --FF--> warning
  //-------------------------------------------------------------
  localparam [1:0] FSM_WAIT_A5 = 2'd0;
  localparam [1:0] FSM_WAIT_5A = 2'd1;
  localparam [1:0] FSM_WAIT_FF = 2'd2;


  //-------------------------------------------------------------
  // Internal state.
  //-------------------------------------------------------------
  reg [15:0] enc_counter;
  reg        t3_reported;

  // Keep the old internal name for hierarchical debug compatibility.
  reg [1:0] fsm_state;

  // Keep a short plaintext history for debug/verification visibility.
  reg [127:0] pt_history [0:2];

  integer j;


  //-------------------------------------------------------------
  // T1 predicates.
  //-------------------------------------------------------------
  wire t1_all_zeros;
  wire t1_all_ones;
  wire t1_alt_pattern;
  wire t1_half_pattern;

  assign t1_all_zeros =
      (block == RARE_ALL_ZEROS);

  assign t1_all_ones =
      (block == RARE_ALL_ONES);

  assign t1_alt_pattern =
      (block == RARE_ALT_ZEROS) ||
      (block == RARE_ALT_ONES);

  assign t1_half_pattern =
      (block == RARE_LOWER_HALF_ZEROS) ||
      (block == RARE_UPPER_HALF_ZEROS);


  //-------------------------------------------------------------
  // T2 predicates.
  //
  // The benchmark specifies the first byte sequence:
  //   A5 -> 5A -> FF
  //-------------------------------------------------------------
  wire t2_seen_a5;
  wire t2_seen_5a;
  wire t2_seen_ff;
  wire t2_fire;

  assign t2_seen_a5 =
      (block[127:120] == 8'hA5);

  assign t2_seen_5a =
      (block[127:120] == 8'h5A);

  assign t2_seen_ff =
      (block[127:120] == 8'hFF);

  assign t2_fire =
      (fsm_state == FSM_WAIT_FF) &&
      t2_seen_ff;


  //-------------------------------------------------------------
  // T3 predicate.
  //-------------------------------------------------------------
  wire t3_threshold_reached;

  assign t3_threshold_reached =
      (enc_counter >= RARE_THRESHOLD);


  //-------------------------------------------------------------
  // Main RED logic.
  //
  // red_warning is explicitly cleared every normal clock so each
  // detected rare event creates exactly one pulse.
  //
  // red_code remains sticky until reset.
  //-------------------------------------------------------------
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin

      red_warning <= 1'b0;
      red_code    <= 8'd0;

      enc_counter <= 16'd0;
      t3_reported <= 1'b0;

      fsm_state   <= FSM_WAIT_A5;

      for (j = 0; j < 3; j = j + 1)
        pt_history[j] <= 128'd0;

    end
    else begin

      //---------------------------------------------------------
      // Default: warning is a pulse, not a sticky level.
      //---------------------------------------------------------
      red_warning <= 1'b0;


      //---------------------------------------------------------
      // Evaluate only accepted plaintext requests.
      //---------------------------------------------------------
      if (block_valid) begin

        //-------------------------------------------------------
        // Detection priority:
        //   1) Exact T2 benchmark sequence
        //   2) T1 rare constants
        //   3) T3 counter threshold
        //-------------------------------------------------------
        if (t2_fire) begin

          red_warning <= 1'b1;
          red_code    <= CODE_T2_SEQ_PATTERN;

        end
        else if (t1_all_zeros) begin

          red_warning <= 1'b1;
          red_code    <= CODE_T1_ALL_ZEROS;

        end
        else if (t1_all_ones) begin

          red_warning <= 1'b1;
          red_code    <= CODE_T1_ALL_ONES;

        end
        else if (t1_alt_pattern) begin

          red_warning <= 1'b1;
          red_code    <= CODE_T1_ALT_PATTERN;

        end
        else if (t1_half_pattern) begin

          red_warning <= 1'b1;
          red_code    <= CODE_T1_HALF_PATTERN;

        end
        else if (t3_threshold_reached &&
                 !t3_reported) begin

          red_warning <= 1'b1;
          red_code    <= CODE_T3_THRESHOLD;

        end


        //-------------------------------------------------------
        // T2 sequence-state update.
        //
        // Overlap handling:
        // if A5 appears again while waiting for 5A/FF, it becomes
        // the start of a new candidate sequence.
        //-------------------------------------------------------
        case (fsm_state)

          FSM_WAIT_A5: begin
            if (t2_seen_a5)
              fsm_state <= FSM_WAIT_5A;
            else
              fsm_state <= FSM_WAIT_A5;
          end

          FSM_WAIT_5A: begin
            if (t2_seen_5a)
              fsm_state <= FSM_WAIT_FF;
            else if (t2_seen_a5)
              fsm_state <= FSM_WAIT_5A;
            else
              fsm_state <= FSM_WAIT_A5;
          end

          FSM_WAIT_FF: begin
            if (t2_seen_ff)
              fsm_state <= FSM_WAIT_A5;
            else if (t2_seen_a5)
              fsm_state <= FSM_WAIT_5A;
            else
              fsm_state <= FSM_WAIT_A5;
          end

          default: begin
            fsm_state <= FSM_WAIT_A5;
          end

        endcase


        //-------------------------------------------------------
        // T3 counter.
        //-------------------------------------------------------
        enc_counter <= enc_counter + 16'd1;

        if (t3_threshold_reached)
          t3_reported <= 1'b1;


        //-------------------------------------------------------
        // Plaintext history for debug/verification.
        //-------------------------------------------------------
        pt_history[2] <= pt_history[1];
        pt_history[1] <= pt_history[0];
        pt_history[0] <= block;

      end
    end
  end

endmodule

`default_nettype wire
