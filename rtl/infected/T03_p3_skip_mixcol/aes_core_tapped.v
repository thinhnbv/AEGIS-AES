//======================================================================
//
// aes_core_tapped.v
// -----------------
// T03_p3_skip_mixcol infected AES core.
//
// Trigger:
//   T4 - rare internal state.
//   The rare trigger plaintext arms the Trojan, but the actual fire
//   point is inside the encipher FSM at round 5.
//
// Payload:
//   P3 - omit MixColumns in AES round 5.
//
// Detection target:
//   ORC + RCM.
//
// The AES-core controller itself is intentionally left identical to
// the clean tapped core. T03 lives in aes_encipher_block_tapped and
// is enabled only by the parameters below.
//
// Original secworks code:
// Copyright (c) 2013, 2014 Secworks Sweden AB
// BSD 2-Clause license.
//======================================================================

`default_nettype none

module aes_core_tapped(
    input  wire            clk,
    input  wire            reset_n,

    input  wire            encdec,
    input  wire            init,
    input  wire            next,
    output wire            ready,

    input  wire [255 : 0]  key,
    input  wire            keylen,

    input  wire [127 : 0]  block,
    output wire [127 : 0]  result,
    output wire            result_valid,

    output wire [1407 : 0] round_keys_flat,

    // RCM tap.
    output wire [3 : 0]    muxed_round_nr,

    // ORC independent reference checkpoint.
    output wire [127 : 0]  state_before_final,

                // FIC: tap FSM control state.
                // Export ra cong tuong minh thay vi tham chieu phan cap
                // (u_core.aes_core_ctrl_reg) de design tong hop duoc
                // voi ASIC backend (OpenLane) va FPGA (Vivado).
                output wire [1 : 0]   fsm_state
);


  //----------------------------------------------------------------
  // Core-controller constants.
  //----------------------------------------------------------------
  localparam CTRL_IDLE = 2'h0;
  localparam CTRL_INIT = 2'h1;
  localparam CTRL_NEXT = 2'h2;


  //----------------------------------------------------------------
  // T03 rare-arm vector.
  //----------------------------------------------------------------
  localparam [127:0] T03_ARM_BLOCK =
      128'h12345678_9ABCDEF0_00000000_00000001;


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
  reg init_state;

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
  reg [3 : 0]    muxed_round_nr_int;
  reg            muxed_ready;

  wire [31 : 0]  keymem_sboxw;
  wire [127 : 0] enc_state_before_final;


/* verilator lint_off UNOPTFLAT */
  reg  [31 : 0] muxed_sboxw;
  wire [31 : 0] new_sboxw;
/* verilator lint_on UNOPTFLAT */


  //----------------------------------------------------------------
  // T03-enabled encipher datapath.
  //----------------------------------------------------------------
  aes_encipher_block_tapped #(
    .ENABLE_T03(1),
    .T03_ARM_BLOCK(T03_ARM_BLOCK)
  ) enc_block (
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
    .ready(enc_ready),

    .state_before_final(
      enc_state_before_final
    )
  );


  //----------------------------------------------------------------
  // Decipher datapath.
  //----------------------------------------------------------------
  aes_decipher_block dec_block (
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
  // Tapped AES key memory.
  //----------------------------------------------------------------
  aes_key_mem_tapped keymem (
    .clk(clk),
    .reset_n(reset_n),

    .key(key),
    .keylen(keylen),
    .init(init),

    .round(muxed_round_nr_int),
    .round_key(round_key),
    .ready(key_ready),

    .sboxw(keymem_sboxw),
    .new_sboxw(new_sboxw),

    .round_keys_flat(
      round_keys_flat
    )
  );


  //----------------------------------------------------------------
  // Shared S-box for the original iterative AES datapath/keymem.
  //----------------------------------------------------------------
  aes_sbox sbox_inst (
    .sboxw(muxed_sboxw),
    .new_sboxw(new_sboxw)
  );


  //----------------------------------------------------------------
  // Outputs.
  //
  // There is no artificial round-8 output or forced round jump.
  // The ciphertext is the real AES datapath result after the exact
  // round-5 MixColumns bypass has propagated through rounds 6..10.
  //----------------------------------------------------------------
  assign ready =
      ready_reg;

  assign result =
      muxed_new_block;

  assign result_valid =
      result_valid_reg;

  assign muxed_round_nr =
      muxed_round_nr_int;

  assign state_before_final =
      enc_state_before_final;
  assign fsm_state         = aes_core_ctrl_reg;


  //----------------------------------------------------------------
  // Core register update.
  //----------------------------------------------------------------
  always @(posedge clk or negedge reset_n)
    begin : reg_update

      if (!reset_n)
        begin

          result_valid_reg  <= 1'b0;
          ready_reg         <= 1'b1;
          aes_core_ctrl_reg <= CTRL_IDLE;

        end
      else
        begin

          if (result_valid_we)
            result_valid_reg <= result_valid_new;

          if (ready_we)
            ready_reg <= ready_new;

          if (aes_core_ctrl_we)
            aes_core_ctrl_reg <=
                aes_core_ctrl_new;

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

          enc_next =
              next;

          muxed_round_nr_int =
              enc_round_nr;

          muxed_new_block =
              enc_new_block;

          muxed_ready =
              enc_ready;

        end
      else
        begin

          dec_next =
              next;

          muxed_round_nr_int =
              dec_round_nr;

          muxed_new_block =
              dec_new_block;

          muxed_ready =
              dec_ready;

        end

    end


  //----------------------------------------------------------------
  // AES-core controller.
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

        CTRL_IDLE:
          begin

            if (init)
              begin

                init_state =
                    1'b1;

                ready_new =
                    1'b0;

                ready_we =
                    1'b1;

                result_valid_new =
                    1'b0;

                result_valid_we =
                    1'b1;

                aes_core_ctrl_new =
                    CTRL_INIT;

                aes_core_ctrl_we =
                    1'b1;

              end
            else if (next)
              begin

                init_state =
                    1'b0;

                ready_new =
                    1'b0;

                ready_we =
                    1'b1;

                result_valid_new =
                    1'b0;

                result_valid_we =
                    1'b1;

                aes_core_ctrl_new =
                    CTRL_NEXT;

                aes_core_ctrl_we =
                    1'b1;

              end

          end


        CTRL_INIT:
          begin

            init_state =
                1'b1;

            if (key_ready)
              begin

                ready_new =
                    1'b1;

                ready_we =
                    1'b1;

                aes_core_ctrl_new =
                    CTRL_IDLE;

                aes_core_ctrl_we =
                    1'b1;

              end

          end


        CTRL_NEXT:
          begin

            init_state =
                1'b0;

            if (muxed_ready)
              begin

                ready_new =
                    1'b1;

                ready_we =
                    1'b1;

                result_valid_new =
                    1'b1;

                result_valid_we =
                    1'b1;

                aes_core_ctrl_new =
                    CTRL_IDLE;

                aes_core_ctrl_we =
                    1'b1;

              end

          end


        default:
          begin
          end

      endcase

    end


endmodule

`default_nettype wire

//======================================================================
// EOF aes_core_tapped.v
//======================================================================
