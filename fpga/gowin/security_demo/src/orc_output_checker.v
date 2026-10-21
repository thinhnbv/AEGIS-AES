//---------------------------------------------------------------
// orc_output_checker.v
//
// Output Redundancy Checker (ORC)
//
// ORC independently recomputes the AES-128 final round:
//
//   SubBytes -> ShiftRows -> AddRoundKey
//
// and compares the recomputed value with core_result.
//
// It also verifies that the final-round checkpoint was actually
// reached. If a Trojan jumps from a pre-final round directly past
// round 10, ORC reports a "final checkpoint bypass" immediately.
// This allows T03 to be detected by both ORC and RCM before TRU
// zeroizes the AES core.
//
// orc_alarm is sticky until rst_n.
//
// Codes:
//   1 = final-round result mismatch
//   2 = final-round checkpoint missing / bypassed
//---------------------------------------------------------------

`default_nettype none
`include "aegis_defs.vh"

module orc_output_checker #(
    parameter integer NUM_ROUNDS = 10
) (
    input  wire         clk,
    input  wire         rst_n,

    input  wire         next,
    input  wire         result_valid,
    input  wire [3:0]   round_nr,

    input  wire [127:0] state_before_final,
    input  wire [127:0] final_round_key,
    input  wire [127:0] core_result,

    output reg          orc_alarm,
    output reg  [3:0]   orc_code
);


  //-------------------------------------------------------------
  // Transaction tracking.
  //-------------------------------------------------------------
  reg          active;
  reg          capture_valid;

  reg [3:0]    prev_round_nr;

  reg [127:0]  captured_state;
  reg [127:0]  captured_final_key;


  //-------------------------------------------------------------
  // Independent SubBytes.
  //
  // aes_sbox operates on one 32-bit word (4 bytes).
  //-------------------------------------------------------------
  wire [31:0] sub_w0;
  wire [31:0] sub_w1;
  wire [31:0] sub_w2;
  wire [31:0] sub_w3;

  aes_sbox sbox_w0 (
    .sboxw(captured_state[127:96]),
    .new_sboxw(sub_w0)
  );

  aes_sbox sbox_w1 (
    .sboxw(captured_state[95:64]),
    .new_sboxw(sub_w1)
  );

  aes_sbox sbox_w2 (
    .sboxw(captured_state[63:32]),
    .new_sboxw(sub_w2)
  );

  aes_sbox sbox_w3 (
    .sboxw(captured_state[31:0]),
    .new_sboxw(sub_w3)
  );


  //-------------------------------------------------------------
  // Independent ShiftRows.
  //
  // This mapping matches the Secworks AES state representation:
  //
  //   w0 = state[127:96]
  //   w1 = state[95:64]
  //   w2 = state[63:32]
  //   w3 = state[31:0]
  //-------------------------------------------------------------
  wire [31:0] shift_w0;
  wire [31:0] shift_w1;
  wire [31:0] shift_w2;
  wire [31:0] shift_w3;

  assign shift_w0 = {
      sub_w0[31:24],
      sub_w1[23:16],
      sub_w2[15:8],
      sub_w3[7:0]
  };

  assign shift_w1 = {
      sub_w1[31:24],
      sub_w2[23:16],
      sub_w3[15:8],
      sub_w0[7:0]
  };

  assign shift_w2 = {
      sub_w2[31:24],
      sub_w3[23:16],
      sub_w0[15:8],
      sub_w1[7:0]
  };

  assign shift_w3 = {
      sub_w3[31:24],
      sub_w0[23:16],
      sub_w1[15:8],
      sub_w2[7:0]
  };


  //-------------------------------------------------------------
  // Independent AddRoundKey.
  //-------------------------------------------------------------
  wire [127:0] computed_final;

  assign computed_final =
      {shift_w0, shift_w1, shift_w2, shift_w3} ^
      captured_final_key;


  //-------------------------------------------------------------
  // A final checkpoint is bypassed when an active transaction
  // moves from a round below NUM_ROUNDS directly to a round above
  // NUM_ROUNDS without ever capturing round 10.
  //
  // Clean Secworks AES transitions:
  //   ... 9 -> 10 -> 11
  //
  // T03 transition:
  //   ... 9 -> 11
  //-------------------------------------------------------------
  wire final_checkpoint_bypass =
      active &&
      !capture_valid &&
      (prev_round_nr < NUM_ROUNDS) &&
      (round_nr > NUM_ROUNDS);


  //-------------------------------------------------------------
  // Main ORC state / alarm logic.
  //-------------------------------------------------------------
  always @(posedge clk or negedge rst_n) begin

    if (!rst_n) begin

      active             <= 1'b0;
      capture_valid      <= 1'b0;

      prev_round_nr      <= 4'd0;

      captured_state     <= 128'd0;
      captured_final_key <= 128'd0;

      orc_alarm          <= 1'b0;
      orc_code           <= 4'd0;

    end
    else begin

      //---------------------------------------------------------
      // Always track previous round number.
      //---------------------------------------------------------
      prev_round_nr <= round_nr;


      //---------------------------------------------------------
      // New encryption transaction.
      //---------------------------------------------------------
      if (next) begin

        active             <= 1'b1;
        capture_valid      <= 1'b0;

        captured_state     <= 128'd0;
        captured_final_key <= 128'd0;

      end


      //---------------------------------------------------------
      // Capture state exactly when entering final round 10.
      //---------------------------------------------------------
      if (active &&
          (round_nr == NUM_ROUNDS) &&
          (prev_round_nr != NUM_ROUNDS) &&
          !capture_valid) begin

        captured_state     <= state_before_final;
        captured_final_key <= final_round_key;
        capture_valid      <= 1'b1;

      end


      //---------------------------------------------------------
      // Early T03 detection:
      // round 10 was bypassed, so ORC cannot establish a valid
      // independent final-round checkpoint.
      //---------------------------------------------------------
      if (final_checkpoint_bypass) begin

        orc_alarm <= 1'b1;
        orc_code  <= 4'd2;

      end


      //---------------------------------------------------------
      // Validate completed result.
      //---------------------------------------------------------
      if (active && result_valid) begin

        active <= 1'b0;


        //-------------------------------------------------------
        // No final-round checkpoint was ever observed.
        //-------------------------------------------------------
        if (!capture_valid) begin

          orc_alarm <= 1'b1;
          orc_code  <= 4'd2;

        end


        //-------------------------------------------------------
        // Independent final-round result disagrees with core.
        //-------------------------------------------------------
        else if (computed_final != core_result) begin

          orc_alarm <= 1'b1;
          orc_code  <= 4'd1;

        end

      end

    end
  end


endmodule

`default_nettype wire
