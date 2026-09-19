//======================================================================
//
// aes_encipher_block.v
// --------------------
// AES encipher datapath derived from secworks/aes.
//
// AEGIS-AES additions:
//   - state_before_final is an independently maintained reference
//     checkpoint used by ORC.
//   - Optional T03 benchmark logic. Disabled by default.
//
// T03 semantics:
//   Trigger class T4:
//     a rare plaintext arms the Trojan, but it fires only at the
//     internal state CTRL_SBOX / round 5 / final S-box word.
//
//   Payload P3:
//     round 5 performs SubBytes -> ShiftRows -> AddRoundKey and
//     deliberately omits MixColumns.
//
//   The bypass also skips the normal CTRL_MAIN cycle for round 5.
//   Therefore the visible round interval is one clock shorter.
//   RCM can detect this control/round timing inconsistency without
//   any artificial round-counter jump.
//
// Original secworks code:
// Copyright (c) 2013, 2014 Secworks Sweden AB
// BSD 2-Clause license.
//======================================================================

`default_nettype none

module aes_encipher_block_tapped #(
    parameter integer ENABLE_T03 = 0,
    parameter [127:0] T03_ARM_BLOCK =
        128'h12345678_9ABCDEF0_00000000_00000001
) (
    input  wire           clk,
    input  wire           reset_n,

    input  wire           next,

    input  wire           keylen,
    output wire [3 : 0]   round,
    input  wire [127 : 0] round_key,

    output wire [31 : 0]  sboxw,
    input  wire [31 : 0]  new_sboxw,

    input  wire [127 : 0] block,
    output wire [127 : 0] new_block,
    output wire           ready,

    // ORC reference state immediately before the final AES round.
    output wire [127 : 0] state_before_final
);


  //----------------------------------------------------------------
  // Internal constants.
  //----------------------------------------------------------------
  localparam AES_128_BIT_KEY = 1'h0;
  localparam AES_256_BIT_KEY = 1'h1;

  localparam AES128_ROUNDS = 4'ha;
  localparam AES256_ROUNDS = 4'he;

  localparam NO_UPDATE         = 3'h0;
  localparam INIT_UPDATE       = 3'h1;
  localparam SBOX_UPDATE       = 3'h2;
  localparam MAIN_UPDATE       = 3'h3;
  localparam FINAL_UPDATE      = 3'h4;
  localparam T03_BYPASS_UPDATE = 3'h5;

  localparam CTRL_IDLE = 2'h0;
  localparam CTRL_INIT = 2'h1;
  localparam CTRL_SBOX = 2'h2;
  localparam CTRL_MAIN = 2'h3;


  //----------------------------------------------------------------
  // AES round functions.
  //----------------------------------------------------------------
  function automatic [7 : 0] gm2(input [7 : 0] op);
    begin
      gm2 = {op[6 : 0], 1'b0} ^
            (8'h1b & {8{op[7]}});
    end
  endfunction


  function automatic [7 : 0] gm3(input [7 : 0] op);
    begin
      gm3 = gm2(op) ^ op;
    end
  endfunction


  function automatic [31 : 0] mixw(input [31 : 0] w);
    reg [7 : 0] b0;
    reg [7 : 0] b1;
    reg [7 : 0] b2;
    reg [7 : 0] b3;

    reg [7 : 0] mb0;
    reg [7 : 0] mb1;
    reg [7 : 0] mb2;
    reg [7 : 0] mb3;

    begin
      b0 = w[31 : 24];
      b1 = w[23 : 16];
      b2 = w[15 : 08];
      b3 = w[07 : 00];

      mb0 = gm2(b0) ^ gm3(b1) ^ b2      ^ b3;
      mb1 = b0      ^ gm2(b1) ^ gm3(b2) ^ b3;
      mb2 = b0      ^ b1      ^ gm2(b2) ^ gm3(b3);
      mb3 = gm3(b0) ^ b1      ^ b2      ^ gm2(b3);

      mixw = {mb0, mb1, mb2, mb3};
    end
  endfunction


  function automatic [127 : 0] mixcolumns(
      input [127 : 0] data
  );
    reg [31 : 0] w0;
    reg [31 : 0] w1;
    reg [31 : 0] w2;
    reg [31 : 0] w3;

    reg [31 : 0] ws0;
    reg [31 : 0] ws1;
    reg [31 : 0] ws2;
    reg [31 : 0] ws3;

    begin
      w0 = data[127 : 096];
      w1 = data[095 : 064];
      w2 = data[063 : 032];
      w3 = data[031 : 000];

      ws0 = mixw(w0);
      ws1 = mixw(w1);
      ws2 = mixw(w2);
      ws3 = mixw(w3);

      mixcolumns = {ws0, ws1, ws2, ws3};
    end
  endfunction


  function automatic [127 : 0] shiftrows(
      input [127 : 0] data
  );
    reg [31 : 0] w0;
    reg [31 : 0] w1;
    reg [31 : 0] w2;
    reg [31 : 0] w3;

    reg [31 : 0] ws0;
    reg [31 : 0] ws1;
    reg [31 : 0] ws2;
    reg [31 : 0] ws3;

    begin
      w0 = data[127 : 096];
      w1 = data[095 : 064];
      w2 = data[063 : 032];
      w3 = data[031 : 000];

      ws0 = {
        w0[31 : 24],
        w1[23 : 16],
        w2[15 : 08],
        w3[07 : 00]
      };

      ws1 = {
        w1[31 : 24],
        w2[23 : 16],
        w3[15 : 08],
        w0[07 : 00]
      };

      ws2 = {
        w2[31 : 24],
        w3[23 : 16],
        w0[15 : 08],
        w1[07 : 00]
      };

      ws3 = {
        w3[31 : 24],
        w0[23 : 16],
        w1[15 : 08],
        w2[07 : 00]
      };

      shiftrows = {ws0, ws1, ws2, ws3};
    end
  endfunction


  function automatic [127 : 0] addroundkey(
      input [127 : 0] data,
      input [127 : 0] rkey
  );
    begin
      addroundkey = data ^ rkey;
    end
  endfunction


  //----------------------------------------------------------------
  // Main datapath registers.
  //----------------------------------------------------------------
  reg [1 : 0] sword_ctr_reg;
  reg [1 : 0] sword_ctr_new;
  reg         sword_ctr_we;
  reg         sword_ctr_inc;
  reg         sword_ctr_rst;

  reg [3 : 0] round_ctr_reg;
  reg [3 : 0] round_ctr_new;
  reg         round_ctr_we;
  reg         round_ctr_rst;
  reg         round_ctr_inc;

  reg [127 : 0] block_new;

  reg [31 : 0] block_w0_reg;
  reg [31 : 0] block_w1_reg;
  reg [31 : 0] block_w2_reg;
  reg [31 : 0] block_w3_reg;

  reg block_w0_we;
  reg block_w1_we;
  reg block_w2_we;
  reg block_w3_we;

  reg ready_reg;
  reg ready_new;
  reg ready_we;

  reg [1 : 0] enc_ctrl_reg;
  reg [1 : 0] enc_ctrl_new;
  reg         enc_ctrl_we;

  reg [2 : 0] update_type;
  reg [31 : 0] muxed_sboxw;


  //----------------------------------------------------------------
  // T03 trigger state.
  //
  // The rare plaintext only arms the benchmark. The actual trigger
  // condition is an internal-state condition at round 5.
  //----------------------------------------------------------------
  reg t03_armed_reg;
  reg t03_fired_reg;

  wire t03_fire;

  assign t03_fire =
      (ENABLE_T03 != 0) &&
      t03_armed_reg &&
      !t03_fired_reg &&
      (enc_ctrl_reg == CTRL_SBOX) &&
      (round_ctr_reg == 4'd5) &&
      (sword_ctr_reg == 2'd3);


  //----------------------------------------------------------------
  // Independent ORC reference checkpoint.
  //
  // The main datapath may be corrupted by T03. This shadow state
  // always executes the correct AES main-round transform, so at
  // round 10 state_before_final is an independent clean reference.
  //----------------------------------------------------------------
  reg [127 : 0] shadow_state_reg;
  reg [127 : 0] shadow_state_new;
  reg           shadow_state_we;

  wire [31:0] shadow_sbox_w0;
  wire [31:0] shadow_sbox_w1;
  wire [31:0] shadow_sbox_w2;
  wire [31:0] shadow_sbox_w3;

  wire [127:0] shadow_subbytes;
  wire [127:0] shadow_shiftrows;
  wire [127:0] shadow_mixcolumns;
  wire [127:0] shadow_main_block;

  aes_sbox shadow_sbox0(
    .sboxw(shadow_state_reg[127:96]),
    .new_sboxw(shadow_sbox_w0)
  );

  aes_sbox shadow_sbox1(
    .sboxw(shadow_state_reg[95:64]),
    .new_sboxw(shadow_sbox_w1)
  );

  aes_sbox shadow_sbox2(
    .sboxw(shadow_state_reg[63:32]),
    .new_sboxw(shadow_sbox_w2)
  );

  aes_sbox shadow_sbox3(
    .sboxw(shadow_state_reg[31:0]),
    .new_sboxw(shadow_sbox_w3)
  );

  assign shadow_subbytes =
      {
        shadow_sbox_w0,
        shadow_sbox_w1,
        shadow_sbox_w2,
        shadow_sbox_w3
      };

  assign shadow_shiftrows =
      shiftrows(shadow_subbytes);

  assign shadow_mixcolumns =
      mixcolumns(shadow_shiftrows);

  assign shadow_main_block =
      addroundkey(
        shadow_mixcolumns,
        round_key
      );


  //----------------------------------------------------------------
  // Outputs.
  //----------------------------------------------------------------
  assign round     = round_ctr_reg;
  assign sboxw     = muxed_sboxw;

  assign new_block =
      {
        block_w0_reg,
        block_w1_reg,
        block_w2_reg,
        block_w3_reg
      };

  assign ready = ready_reg;

  // IMPORTANT:
  // This is the independently maintained clean pre-final checkpoint
  // used by ORC, not the potentially infected main datapath state.
  assign state_before_final =
      shadow_state_reg;


  //----------------------------------------------------------------
  // Register update.
  //----------------------------------------------------------------
  always @(posedge clk or negedge reset_n)
    begin : reg_update

      if (!reset_n)
        begin

          block_w0_reg     <= 32'h0;
          block_w1_reg     <= 32'h0;
          block_w2_reg     <= 32'h0;
          block_w3_reg     <= 32'h0;

          sword_ctr_reg    <= 2'h0;
          round_ctr_reg    <= 4'h0;

          ready_reg        <= 1'b1;
          enc_ctrl_reg     <= CTRL_IDLE;

          t03_armed_reg    <= 1'b0;
          t03_fired_reg    <= 1'b0;

          shadow_state_reg <= 128'd0;

        end
      else
        begin

          if (block_w0_we)
            block_w0_reg <= block_new[127 : 096];

          if (block_w1_we)
            block_w1_reg <= block_new[095 : 064];

          if (block_w2_we)
            block_w2_reg <= block_new[063 : 032];

          if (block_w3_we)
            block_w3_reg <= block_new[031 : 000];

          if (sword_ctr_we)
            sword_ctr_reg <= sword_ctr_new;

          if (round_ctr_we)
            round_ctr_reg <= round_ctr_new;

          if (ready_we)
            ready_reg <= ready_new;

          if (enc_ctrl_we)
            enc_ctrl_reg <= enc_ctrl_new;

          if (shadow_state_we)
            shadow_state_reg <= shadow_state_new;


          //------------------------------------------------------
          // Arm T03 only at the start of a new encryption.
          //------------------------------------------------------
          if (next && (enc_ctrl_reg == CTRL_IDLE))
            begin
              if ((ENABLE_T03 != 0) &&
                  (block == T03_ARM_BLOCK))
                t03_armed_reg <= 1'b1;
              else
                t03_armed_reg <= 1'b0;

              t03_fired_reg <= 1'b0;
            end


          //------------------------------------------------------
          // Actual T4 fire point.
          //------------------------------------------------------
          if (t03_fire)
            begin
              t03_fired_reg <= 1'b1;
              t03_armed_reg <= 1'b0;
            end

        end
    end


  //----------------------------------------------------------------
  // Main round logic.
  //----------------------------------------------------------------
  always @*
    begin : round_logic

      reg [127 : 0] old_block;
      reg [127 : 0] shiftrows_block;
      reg [127 : 0] mixcolumns_block;

      reg [127 : 0] addkey_init_block;
      reg [127 : 0] addkey_main_block;
      reg [127 : 0] addkey_final_block;

      reg [127 : 0] t03_complete_sbox;
      reg [127 : 0] t03_shiftrows_block;
      reg [127 : 0] t03_bypass_block;


      block_new   = 128'h0;
      muxed_sboxw = 32'h0;

      block_w0_we = 1'b0;
      block_w1_we = 1'b0;
      block_w2_we = 1'b0;
      block_w3_we = 1'b0;


      old_block =
          {
            block_w0_reg,
            block_w1_reg,
            block_w2_reg,
            block_w3_reg
          };

      shiftrows_block =
          shiftrows(old_block);

      mixcolumns_block =
          mixcolumns(shiftrows_block);

      addkey_init_block =
          addroundkey(
            block,
            round_key
          );

      addkey_main_block =
          addroundkey(
            mixcolumns_block,
            round_key
          );

      addkey_final_block =
          addroundkey(
            shiftrows_block,
            round_key
          );


      //----------------------------------------------------------
      // At the T03 fire cycle words 0..2 have already completed
      // SubBytes and new_sboxw is the SubBytes result for word 3.
      //----------------------------------------------------------
      t03_complete_sbox =
          {
            block_w0_reg,
            block_w1_reg,
            block_w2_reg,
            new_sboxw
          };

      t03_shiftrows_block =
          shiftrows(t03_complete_sbox);

      // Exact P3 payload: omit MixColumns, preserve AddRoundKey.
      t03_bypass_block =
          addroundkey(
            t03_shiftrows_block,
            round_key
          );


      case (update_type)

        INIT_UPDATE:
          begin

            block_new =
                addkey_init_block;

            block_w0_we = 1'b1;
            block_w1_we = 1'b1;
            block_w2_we = 1'b1;
            block_w3_we = 1'b1;

          end


        SBOX_UPDATE:
          begin

            block_new =
                {
                  new_sboxw,
                  new_sboxw,
                  new_sboxw,
                  new_sboxw
                };

            case (sword_ctr_reg)

              2'h0:
                begin
                  muxed_sboxw = block_w0_reg;
                  block_w0_we = 1'b1;
                end

              2'h1:
                begin
                  muxed_sboxw = block_w1_reg;
                  block_w1_we = 1'b1;
                end

              2'h2:
                begin
                  muxed_sboxw = block_w2_reg;
                  block_w2_we = 1'b1;
                end

              2'h3:
                begin
                  muxed_sboxw = block_w3_reg;
                  block_w3_we = 1'b1;
                end

            endcase

          end


        MAIN_UPDATE:
          begin

            block_new =
                addkey_main_block;

            block_w0_we = 1'b1;
            block_w1_we = 1'b1;
            block_w2_we = 1'b1;
            block_w3_we = 1'b1;

          end


        FINAL_UPDATE:
          begin

            block_new =
                addkey_final_block;

            block_w0_we = 1'b1;
            block_w1_we = 1'b1;
            block_w2_we = 1'b1;
            block_w3_we = 1'b1;

          end


        //--------------------------------------------------------
        // T03 payload.
        //
        // The normal MAIN_UPDATE would execute:
        //   ShiftRows -> MixColumns -> AddRoundKey
        //
        // This path executes:
        //   ShiftRows -> AddRoundKey
        //
        // Therefore MixColumns is genuinely skipped at round 5.
        //--------------------------------------------------------
        T03_BYPASS_UPDATE:
          begin

            // Feed the external S-box with the final word.
            muxed_sboxw =
                block_w3_reg;

            block_new =
                t03_bypass_block;

            block_w0_we = 1'b1;
            block_w1_we = 1'b1;
            block_w2_we = 1'b1;
            block_w3_we = 1'b1;

          end


        default:
          begin
          end

      endcase

    end


  //----------------------------------------------------------------
  // Shadow/reference state update logic.
  //----------------------------------------------------------------
  always @*
    begin : shadow_ctrl

      shadow_state_new = shadow_state_reg;
      shadow_state_we  = 1'b0;


      //----------------------------------------------------------
      // Initial AddRoundKey.
      //----------------------------------------------------------
      if (enc_ctrl_reg == CTRL_INIT)
        begin

          shadow_state_new =
              addroundkey(
                block,
                round_key
              );

          shadow_state_we = 1'b1;

        end


      //----------------------------------------------------------
      // Correct main round.
      //----------------------------------------------------------
      else if ((enc_ctrl_reg == CTRL_MAIN) &&
               (round_ctr_reg <
                ((keylen == AES_256_BIT_KEY)
                    ? AES256_ROUNDS
                    : AES128_ROUNDS)))
        begin

          shadow_state_new =
              shadow_main_block;

          shadow_state_we = 1'b1;

        end


      //----------------------------------------------------------
      // T03 skips the main CTRL_MAIN cycle at round 5, but the
      // reference path must still execute the correct round 5.
      //----------------------------------------------------------
      else if (t03_fire)
        begin

          shadow_state_new =
              shadow_main_block;

          shadow_state_we = 1'b1;

        end

    end


  //----------------------------------------------------------------
  // SubBytes word counter.
  //----------------------------------------------------------------
  always @*
    begin : sword_ctr

      sword_ctr_new = 2'h0;
      sword_ctr_we  = 1'b0;

      if (sword_ctr_rst)
        begin

          sword_ctr_new = 2'h0;
          sword_ctr_we  = 1'b1;

        end
      else if (sword_ctr_inc)
        begin

          sword_ctr_new =
              sword_ctr_reg + 1'b1;

          sword_ctr_we = 1'b1;

        end

    end


  //----------------------------------------------------------------
  // AES round counter.
  //
  // No T03-specific jump exists here. The counter remains monotonic
  // and increments by exactly one.
  //----------------------------------------------------------------
  always @*
    begin : round_ctr

      round_ctr_new = 4'h0;
      round_ctr_we  = 1'b0;

      if (round_ctr_rst)
        begin

          round_ctr_new = 4'h0;
          round_ctr_we  = 1'b1;

        end
      else if (round_ctr_inc)
        begin

          round_ctr_new =
              round_ctr_reg + 4'd1;

          round_ctr_we = 1'b1;

        end

    end


  //----------------------------------------------------------------
  // Encipher controller.
  //----------------------------------------------------------------
  always @*
    begin : encipher_ctrl

      reg [3 : 0] num_rounds;


      sword_ctr_inc = 1'b0;
      sword_ctr_rst = 1'b0;

      round_ctr_inc = 1'b0;
      round_ctr_rst = 1'b0;

      ready_new = 1'b0;
      ready_we  = 1'b0;

      update_type = NO_UPDATE;

      enc_ctrl_new = CTRL_IDLE;
      enc_ctrl_we  = 1'b0;


      if (keylen == AES_256_BIT_KEY)
        num_rounds = AES256_ROUNDS;
      else
        num_rounds = AES128_ROUNDS;


      case (enc_ctrl_reg)

        CTRL_IDLE:
          begin

            if (next)
              begin

                round_ctr_rst = 1'b1;

                ready_new = 1'b0;
                ready_we  = 1'b1;

                enc_ctrl_new = CTRL_INIT;
                enc_ctrl_we  = 1'b1;

              end

          end


        CTRL_INIT:
          begin

            round_ctr_inc = 1'b1;
            sword_ctr_rst = 1'b1;

            update_type = INIT_UPDATE;

            enc_ctrl_new = CTRL_SBOX;
            enc_ctrl_we  = 1'b1;

          end


        CTRL_SBOX:
          begin

            sword_ctr_inc = 1'b1;
            update_type   = SBOX_UPDATE;


            if (sword_ctr_reg == 2'h3)
              begin

                //------------------------------------------------
                // T03:
                // collapse the round-5 MAIN stage into this final
                // S-box cycle while omitting MixColumns.
                //------------------------------------------------
                if (t03_fire)
                  begin

                    sword_ctr_inc = 1'b0;
                    sword_ctr_rst = 1'b1;

                    round_ctr_inc = 1'b1;

                    update_type =
                        T03_BYPASS_UPDATE;

                    enc_ctrl_new =
                        CTRL_SBOX;

                    enc_ctrl_we =
                        1'b1;

                  end
                else
                  begin

                    enc_ctrl_new =
                        CTRL_MAIN;

                    enc_ctrl_we =
                        1'b1;

                  end

              end

          end


        CTRL_MAIN:
          begin

            sword_ctr_rst = 1'b1;
            round_ctr_inc = 1'b1;


            if (round_ctr_reg < num_rounds)
              begin

                update_type =
                    MAIN_UPDATE;

                enc_ctrl_new =
                    CTRL_SBOX;

                enc_ctrl_we =
                    1'b1;

              end
            else
              begin

                update_type =
                    FINAL_UPDATE;

                ready_new =
                    1'b1;

                ready_we =
                    1'b1;

                enc_ctrl_new =
                    CTRL_IDLE;

                enc_ctrl_we =
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
// EOF aes_encipher_block.v
//======================================================================
