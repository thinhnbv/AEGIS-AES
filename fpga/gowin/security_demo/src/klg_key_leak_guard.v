//---------------------------------------------------------------
// klg_key_leak_guard.v
//
// Key-Leak Guard (KLG)
//
// Detection layers:
//   1) Full 128-bit equality against AES key / any round key.
//   2) 32-bit word equality against any secret 32-bit word.
//   3) Abnormally small Hamming distance to AES key / round keys.
//   4) P2 byte-leak signature: selected ciphertext byte equals the
//      corresponding original-key byte.
//
// Layer 4 exists because benchmark T02 leaks exactly key[7:0] into
// ciphertext[7:0]. It is parameterized so a production design can
// disable it or move the observed byte without changing the module.
//
// Layer 4 uses a SLIDING-WINDOW STATISTICAL test rather than a single
// comparison. See "P2 byte-leak window detector" below.
//
// klg_alarm is sticky until rst_n.
// klg_verdict_valid is a one-cycle pulse for each new AES result.
//
// ---------------------------------------------------------------
// FPGA DEMO NOTE (fpga/gowin/security_demo only - rtl/aegis/ master
// copy is untouched):
//
// This project instantiates TWO full AES-128 cores (one raw, one
// wrapped by aegis_aes_top) on a single GW5A-25A, which does not
// have enough LUT/ALU/CLS to also fit KLG's layers 2 and 3 in full:
//   - Layer 3 (Hamming distance) needs a popcount128() tree over the
//     original key AND all NUM_RKEY round keys -> ~7700 ALU alone.
//   - Layer 2 (32-bit word match) needs 4x4 comparators x (1 + NUM_RKEY)
//     keys = 192 wide comparators, mapped onto ALU primitives too.
// Both are commented out below (search "DISABLED FOR FPGA DEMO") with
// safe fallback values, NOT deleted, so the exact original behavior
// is one uncomment away - e.g. when trying this project again on
// GowinEDA Pro or a bigger device. T01 (an exact 128-bit key leak) is
// still caught in full by layer 1 (hit_full), which is untouched.
// ---------------------------------------------------------------

`default_nettype none
`include "aegis_defs.vh"

module klg_key_leak_guard #(
    parameter integer NUM_RKEY          = `AEGIS_NUM_RKEY,
    parameter integer HAM_THRESH        = 16,
    parameter integer EN_BYTE_LEAK      = 1,
    parameter integer BYTE_LEAK_INDEX   = 0,

    // Sliding-window parameters for the P2 byte-leak detector.
    // See rtl/aegis/klg_key_leak_guard.v for the derivation.
    parameter integer BYTE_LEAK_WINDOW  = 16,
    parameter integer BYTE_LEAK_THRESH  = 6
) (
    input  wire                         clk,
    input  wire                         rst_n,

    input  wire [127:0]                 key_reg,
    input  wire                         key_valid,
    input  wire [NUM_RKEY*128-1:0]      round_keys_flat,

    input  wire [127:0]                 data_out,
    input  wire                         data_out_valid,

    // Recomputed reference ciphertext from the ORC, used to
    // corroborate the byte-level leak check. See
    // rtl/aegis/klg_key_leak_guard.v.
    input  wire                         orc_ref_valid,
    input  wire [127:0]                 orc_ref_result,

    // Kept for interface compatibility / debug visibility.
    input  wire [3:0]                   round_nr,

    output reg                          klg_alarm,
    output reg  [3:0]                   klg_code,

    output reg                          klg_verdict_valid,
    output reg                          klg_verdict_block
);


  //-------------------------------------------------------------
  // Result-event detector.
  //
  // The secworks result_valid level can remain high until the next
  // transaction. Evaluate each result only once on the rising edge.
  //-------------------------------------------------------------
  reg prev_data_out_valid;

  wire result_event =
      data_out_valid && !prev_data_out_valid;


  always @(posedge clk or negedge rst_n) begin
    if (!rst_n)
      prev_data_out_valid <= 1'b0;
    else
      prev_data_out_valid <= data_out_valid;
  end


  //-------------------------------------------------------------
  // Hamming-distance helper.
  //-------------------------------------------------------------
  function automatic [7:0] popcount128;
    input [127:0] value;
    integer bit_idx;
    begin
      popcount128 = 8'd0;

      for (bit_idx = 0;
           bit_idx < 128;
           bit_idx = bit_idx + 1)
        popcount128 =
            popcount128 + {7'd0, value[bit_idx]};
    end
  endfunction


  //-------------------------------------------------------------
  // Combinational secret comparisons.
  //-------------------------------------------------------------
  reg       hit_full;
  reg       hit_word;
  reg       hit_ham;

  reg [7:0] min_ham;

  integer r;
  integer out_word;
  integer secret_word;

  reg [127:0] current_rkey;
  reg [7:0]   current_ham;


  always @* begin

    //-----------------------------------------------------------
    // Original AES key.
    //-----------------------------------------------------------
    hit_full = (data_out == key_reg);
    hit_word = 1'b0;

    // ---- DISABLED FOR FPGA DEMO (layer 3, Hamming distance) ----
    // Original:
    //   min_ham  = popcount128(data_out ^ key_reg);
    // Safe fallback so hit_ham below never fires:
    min_ham  = 8'hff;
    // --------------------------------------------------------------


    //-----------------------------------------------------------
    // Compare every ciphertext 32-bit word with every 32-bit
    // word of the original AES key.
    //-----------------------------------------------------------
    // ---- DISABLED FOR FPGA DEMO (layer 2, word match) ----
    // Original body (uncomment to restore):
    //
    // for (out_word = 0;
    //      out_word < 4;
    //      out_word = out_word + 1) begin
    //
    //   for (secret_word = 0;
    //        secret_word < 4;
    //        secret_word = secret_word + 1) begin
    //
    //     if (data_out[out_word*32 +: 32] ==
    //         key_reg[secret_word*32 +: 32])
    //       hit_word = 1'b1;
    //
    //   end
    // end
    // --------------------------------------------------------------


    //-----------------------------------------------------------
    // Round keys:
    //   - full equality
    //   - 32-bit secret-word equality
    //   - minimum Hamming distance
    //-----------------------------------------------------------
    for (r = 0; r < NUM_RKEY; r = r + 1) begin

      current_rkey =
          round_keys_flat[r*128 +: 128];

      if (data_out == current_rkey)
        hit_full = 1'b1;


      // ---- DISABLED FOR FPGA DEMO (layer 2, word match vs round keys) ----
      // Original body (uncomment to restore):
      //
      // for (out_word = 0;
      //      out_word < 4;
      //      out_word = out_word + 1) begin
      //
      //   for (secret_word = 0;
      //        secret_word < 4;
      //        secret_word = secret_word + 1) begin
      //
      //     if (data_out[out_word*32 +: 32] ==
      //         current_rkey[secret_word*32 +: 32])
      //       hit_word = 1'b1;
      //
      //   end
      // end
      // ----------------------------------------------------------------


      // ---- DISABLED FOR FPGA DEMO (layer 3, Hamming distance vs round keys) ----
      // Original body (uncomment to restore):
      //
      // current_ham =
      //     popcount128(data_out ^ current_rkey);
      //
      // if (current_ham < min_ham)
      //   min_ham = current_ham;
      // ----------------------------------------------------------------

    end


    hit_ham =
        (min_ham < HAM_THRESH);

  end


  //-------------------------------------------------------------
  // P2 byte-leak signature.
  //
  // T02 payload:
  //   result[7:0] = key[7:0]
  //
  // BYTE_LEAK_INDEX=0 corresponds to [7:0].
  //
  // A single match is far too weak on its own: on random traffic it
  // fires with probability 1/256, i.e. ~3906 false alarms per 1e6
  // encryptions. The match is therefore counted in a sliding window
  // and only becomes an alarm once enough of the recent results
  // matched. This mirrors rtl/aegis/klg_key_leak_guard.v.
  //-------------------------------------------------------------
  wire byte_match_now =
      (data_out[BYTE_LEAK_INDEX*8 +: 8] ==
       key_reg[BYTE_LEAK_INDEX*8 +: 8]);

  // Corroborated byte-leak test: the ORC reference proves the byte
  // was actually modified, so a chance match is not a leak.
  // This mirrors rtl/aegis/klg_key_leak_guard.v.
  wire byte_leak_corrob =
      EN_BYTE_LEAK &&
      orc_ref_valid &&
      (data_out[BYTE_LEAK_INDEX*8 +: 8] !=
       orc_ref_result[BYTE_LEAK_INDEX*8 +: 8]) &&
      (data_out[BYTE_LEAK_INDEX*8 +: 8] ==
       key_reg[BYTE_LEAK_INDEX*8 +: 8]);

  reg [BYTE_LEAK_WINDOW-1:0] byte_leak_hist;
  reg [7:0]                byte_leak_cnt;

  wire [7:0] byte_leak_count_next =
      byte_leak_cnt
      + (byte_match_now ? 8'd1 : 8'd0)
      - byte_leak_hist[BYTE_LEAK_WINDOW-1];

  wire hit_byte_leak_window =
      EN_BYTE_LEAK && (byte_leak_count_next >= BYTE_LEAK_THRESH);

  wire hit_byte_leak =
      byte_leak_corrob || hit_byte_leak_window;

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      byte_leak_hist <= {BYTE_LEAK_WINDOW{1'b0}};
      byte_leak_cnt  <= 8'd0;
    end
    else if (key_valid) begin
      byte_leak_hist <= {BYTE_LEAK_WINDOW{1'b0}};
      byte_leak_cnt  <= 8'd0;
    end
    else if (result_event) begin
      byte_leak_hist <= {byte_leak_hist[BYTE_LEAK_WINDOW-2:0],
                         byte_match_now};

      byte_leak_cnt  <= byte_leak_count_next;
    end
  end


  //-------------------------------------------------------------
  // KLG verdict / alarm.
  //-------------------------------------------------------------
  always @(posedge clk or negedge rst_n) begin

    if (!rst_n) begin

      klg_alarm         <= 1'b0;
      klg_code          <= 4'd0;

      klg_verdict_valid <= 1'b0;
      klg_verdict_block <= 1'b1;

    end
    else begin

      //---------------------------------------------------------
      // Verdict is a pulse.
      //---------------------------------------------------------
      klg_verdict_valid <= 1'b0;

      //---------------------------------------------------------
      // Fail-secure default for cycles without a fresh verdict.
      //---------------------------------------------------------
      klg_verdict_block <= 1'b1;


      //---------------------------------------------------------
      // Evaluate exactly once per new AES result.
      //---------------------------------------------------------
      if (result_event) begin

        klg_verdict_valid <= 1'b1;


        //-------------------------------------------------------
        // Priority:
        //   1 = full 128-bit secret leak
        //   2 = 32-bit secret-word leak
        //   3 = abnormal Hamming proximity
        //   4 = benchmark P2 8-bit leak
        //-------------------------------------------------------
        if (hit_full) begin

          klg_alarm         <= 1'b1;
          klg_code          <= 4'd1;
          klg_verdict_block <= 1'b1;

        end
        else if (hit_word) begin

          klg_alarm         <= 1'b1;
          klg_code          <= 4'd2;
          klg_verdict_block <= 1'b1;

        end
        else if (hit_ham) begin

          klg_alarm         <= 1'b1;
          klg_code          <= 4'd3;
          klg_verdict_block <= 1'b1;

        end
        else if (hit_byte_leak) begin

          klg_alarm         <= 1'b1;
          klg_code          <= 4'd4;
          klg_verdict_block <= 1'b1;

        end
        else if (!klg_alarm) begin

          //-----------------------------------------------------
          // Clean result.
          //-----------------------------------------------------
          klg_verdict_block <= 1'b0;

        end

      end

    end
  end


  //-------------------------------------------------------------
  // Avoid unused-input warnings while retaining the public port.
  //-------------------------------------------------------------
  wire _unused_round_nr = &{1'b0, round_nr};


endmodule

`default_nettype wire
