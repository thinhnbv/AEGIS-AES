// ============================================================================
// Project     : AEGIS-AES
// Module      : raw_aes_adapter
// Description : Adapt the secworks AES core interface to the simple demo
//               interface. This path intentionally has no KLG, TRU,
//               quarantine, or zeroization.
// ============================================================================

`default_nettype none

module raw_aes_adapter (
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

  //----------------------------------------------------------------
  // State encoding.
  //----------------------------------------------------------------
  localparam [2:0] ST_IDLE             = 3'd0;
  localparam [2:0] ST_WAIT_KEY_BUSY    = 3'd1;
  localparam [2:0] ST_WAIT_KEY_DONE    = 3'd2;
  localparam [2:0] ST_READY            = 3'd3;
  localparam [2:0] ST_WAIT_RESULT_LOW  = 3'd4;
  localparam [2:0] ST_WAIT_RESULT_HIGH = 3'd5;

  //----------------------------------------------------------------
  // Adapter registers.
  //----------------------------------------------------------------
  reg [2:0] state_reg;

  reg [127:0] key_reg;
  reg [127:0] block_reg;

  reg core_init_reg;
  reg core_next_reg;
  reg busy_reg;

  reg [127:0] data_out_reg;
  reg         data_out_valid_reg;

  //----------------------------------------------------------------
  // AES core signals.
  //----------------------------------------------------------------
  wire         core_ready;
  wire [127:0] core_result;
  wire         core_result_valid;

  // Raw path does not inspect the AES round keys.
  /* verilator lint_off UNUSEDSIGNAL */
  wire [1407:0] round_keys_unused;
  /* verilator lint_on UNUSEDSIGNAL */

  //----------------------------------------------------------------
  // Tapped AES core.
  //
  // The selected build source decides whether this is the clean
  // implementation or the T01-infected implementation.
  //----------------------------------------------------------------
  aes_core_tapped u_core (
    .clk(clk),
    .reset_n(rst_n),

    .encdec(1'b1),
    .init(core_init_reg),
    .next(core_next_reg),
    .ready(core_ready),

    .key({key_reg, key_reg}),
    .keylen(1'b0),

    .block(block_reg),
    .result(core_result),
    .result_valid(core_result_valid),
    .round_keys_flat(round_keys_unused)
  );

  //----------------------------------------------------------------
  // Adapter FSM.
  //----------------------------------------------------------------
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state_reg <= ST_IDLE;

      key_reg <= 128'd0;
      block_reg <= 128'd0;

      core_init_reg <= 1'b0;
      core_next_reg <= 1'b0;
      busy_reg <= 1'b0;

      data_out_reg <= 128'd0;
      data_out_valid_reg <= 1'b0;
    end else begin
      // Control and output-valid signals are one-clock pulses.
      core_init_reg <= 1'b0;
      core_next_reg <= 1'b0;
      data_out_valid_reg <= 1'b0;

      case (state_reg)
        //----------------------------------------------------------
        // No key has been loaded after reset.
        //----------------------------------------------------------
        ST_IDLE: begin
          busy_reg <= 1'b0;

          if (key_valid) begin
            key_reg <= key;
            core_init_reg <= 1'b1;
            busy_reg <= 1'b1;
            state_reg <= ST_WAIT_KEY_BUSY;
          end
        end

        //----------------------------------------------------------
        // Wait for the core to accept key initialization.
        //----------------------------------------------------------
        ST_WAIT_KEY_BUSY: begin
          busy_reg <= 1'b1;

          if (!core_ready)
            state_reg <= ST_WAIT_KEY_DONE;
        end

        //----------------------------------------------------------
        // Wait for key expansion to finish.
        //----------------------------------------------------------
        ST_WAIT_KEY_DONE: begin
          busy_reg <= 1'b1;

          if (core_ready) begin
            busy_reg <= 1'b0;
            state_reg <= ST_READY;
          end
        end

        //----------------------------------------------------------
        // Accept either a new key or one data block.
        //----------------------------------------------------------
        ST_READY: begin
          busy_reg <= 1'b0;

          if (key_valid) begin
            key_reg <= key;
            core_init_reg <= 1'b1;
            busy_reg <= 1'b1;
            state_reg <= ST_WAIT_KEY_BUSY;
          end else if (data_in_valid) begin
            block_reg <= data_in;
            core_next_reg <= 1'b1;
            busy_reg <= 1'b1;
            state_reg <= ST_WAIT_RESULT_LOW;
          end
        end

        //----------------------------------------------------------
        // A previous result_valid may still be high.
        // Wait for it to return low before accepting a new result.
        //----------------------------------------------------------
        ST_WAIT_RESULT_LOW: begin
          busy_reg <= 1'b1;

          if (!core_result_valid)
            state_reg <= ST_WAIT_RESULT_HIGH;
        end

        //----------------------------------------------------------
        // Capture exactly one new AES result.
        //----------------------------------------------------------
        ST_WAIT_RESULT_HIGH: begin
          busy_reg <= 1'b1;

          if (core_result_valid) begin
            data_out_reg <= core_result;
            data_out_valid_reg <= 1'b1;

            busy_reg <= 1'b0;
            state_reg <= ST_READY;
          end
        end

        //----------------------------------------------------------
        // Fail-safe recovery.
        //----------------------------------------------------------
        default: begin
          state_reg <= ST_IDLE;

          key_reg <= 128'd0;
          block_reg <= 128'd0;

          core_init_reg <= 1'b0;
          core_next_reg <= 1'b0;
          busy_reg <= 1'b0;

          data_out_reg <= 128'd0;
          data_out_valid_reg <= 1'b0;
        end
      endcase
    end
  end

  //----------------------------------------------------------------
  // Outputs.
  //----------------------------------------------------------------
  assign data_out = data_out_reg;
  assign data_out_valid = data_out_valid_reg;
  assign busy = busy_reg;

endmodule

`default_nettype wire
