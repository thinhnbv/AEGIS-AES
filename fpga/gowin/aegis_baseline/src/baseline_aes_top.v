//---------------------------------------------------------------
// baseline_aes_top.v
// Baseline AES-128 wrapper for FPGA resource/timing comparison.
//
// Purpose:
//   - Provide the same simple key/data handshake style as aegis_aes_top.
//   - Instantiate the clean secworks AES core (aes_core), not aes_core_tapped.
//   - Do NOT include KLG/FIC/RCM/RED/ORC/TRU, zeroize, security status,
//     round-key taps, or other AEGIS protection logic.
//
// AES mode:
//   - AES-128 only
//   - Encryption only
//---------------------------------------------------------------

`default_nettype none

module baseline_aes_top (
    input  wire         clk,
    input  wire         rst_n,

    input  wire [127:0] key,
    input  wire         key_valid,

    input  wire [127:0] data_in,
    input  wire         data_in_valid,

    output wire [127:0] data_out,
    output wire         data_out_valid,
    output wire         busy
);

  //-------------------------------------------------------------
  // Wrapper state machine.
  //-------------------------------------------------------------
  localparam ST_IDLE             = 3'd0;
  localparam ST_WAIT_KEY_BUSY    = 3'd1;
  localparam ST_WAIT_KEY_DONE    = 3'd2;
  localparam ST_READY            = 3'd3;
  localparam ST_WAIT_RESULT_LOW  = 3'd4;
  localparam ST_WAIT_RESULT_HIGH = 3'd5;

  reg [2:0] state;

  //-------------------------------------------------------------
  // Input/control registers.
  //-------------------------------------------------------------
  reg [127:0] key_reg;
  reg [127:0] block_reg;

  reg         core_init;
  reg         core_next;
  reg         busy_reg;

  //-------------------------------------------------------------
  // Clean secworks AES core signals.
  //-------------------------------------------------------------
  wire         core_ready;
  wire [127:0] core_dout;
  wire         core_dvalid;

  //-------------------------------------------------------------
  // AES-128 encryption core.
  //
  // keylen = 0 : AES-128
  // encdec = 1 : encryption
  //
  // The 128-bit key is duplicated into the 256-bit secworks key
  // port. With keylen=0 only the AES-128 key is selected; using the
  // duplicated value also keeps the mapping consistent with the
  // protected AEGIS wrapper.
  //-------------------------------------------------------------
  aes_core u_core (
      .clk          (clk),
      .reset_n      (rst_n),

      .encdec       (1'b1),
      .init         (core_init),
      .next         (core_next),
      .ready        (core_ready),

      .key          ({key_reg, key_reg}),
      .keylen       (1'b0),

      .block        (block_reg),
      .result       (core_dout),
      .result_valid (core_dvalid)
  );

  //-------------------------------------------------------------
  // Wrapper controller.
  //-------------------------------------------------------------
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state     <= ST_IDLE;
      key_reg   <= 128'd0;
      block_reg <= 128'd0;
      core_init <= 1'b0;
      core_next <= 1'b0;
      busy_reg  <= 1'b0;
    end else begin
      // init/next are one-cycle pulses.
      core_init <= 1'b0;
      core_next <= 1'b0;

      case (state)

        //-------------------------------------------------------
        // No key has been initialized yet.
        //-------------------------------------------------------
        ST_IDLE: begin
          busy_reg <= 1'b0;

          if (key_valid) begin
            key_reg   <= key;
            core_init <= 1'b1;
            busy_reg  <= 1'b1;
            state     <= ST_WAIT_KEY_BUSY;
          end
        end

        //-------------------------------------------------------
        // Wait for aes_core to acknowledge key expansion start.
        //-------------------------------------------------------
        ST_WAIT_KEY_BUSY: begin
          busy_reg <= 1'b1;

          if (!core_ready)
            state <= ST_WAIT_KEY_DONE;
        end

        //-------------------------------------------------------
        // Wait for AES-128 key expansion to complete.
        //-------------------------------------------------------
        ST_WAIT_KEY_DONE: begin
          busy_reg <= 1'b1;

          if (core_ready) begin
            busy_reg <= 1'b0;
            state    <= ST_READY;
          end
        end

        //-------------------------------------------------------
        // Ready for a new key or plaintext block.
        //-------------------------------------------------------
        ST_READY: begin
          busy_reg <= 1'b0;

          // Give key reload priority over a new plaintext.
          if (key_valid) begin
            key_reg   <= key;
            core_init <= 1'b1;
            busy_reg  <= 1'b1;
            state     <= ST_WAIT_KEY_BUSY;
          end
          else if (data_in_valid) begin
            block_reg <= data_in;
            core_next <= 1'b1;
            busy_reg  <= 1'b1;
            state     <= ST_WAIT_RESULT_LOW;
          end
        end

        //-------------------------------------------------------
        // result_valid can still reflect a previous operation for
        // a short interval. First wait until it is low.
        //-------------------------------------------------------
        ST_WAIT_RESULT_LOW: begin
          busy_reg <= 1'b1;

          if (!core_dvalid)
            state <= ST_WAIT_RESULT_HIGH;
        end

        //-------------------------------------------------------
        // Wait for the fresh ciphertext.
        //-------------------------------------------------------
        ST_WAIT_RESULT_HIGH: begin
          busy_reg <= 1'b1;

          if (core_dvalid) begin
            busy_reg <= 1'b0;
            state    <= ST_READY;
          end
        end

        default: begin
          state    <= ST_IDLE;
          busy_reg <= 1'b0;
        end

      endcase
    end
  end

  //-------------------------------------------------------------
  // Baseline output: no security hold/block stage.
  //-------------------------------------------------------------
  assign data_out       = core_dout;
  assign data_out_valid = core_dvalid;
  assign busy           = busy_reg;

endmodule

`default_nettype wire
