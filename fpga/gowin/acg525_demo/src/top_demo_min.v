// ============================================================================
// Project     : AEGIS-AES
// Module      : top_demo_min
// Description : Minimal test: AES core with fixed key/plaintext, auto-encrypt.
//               Debug LEDs show result correctness.
// ============================================================================

`default_nettype none

module top_demo_min (
  input  wire clk,
  input  wire key0_n,

  output wire led0,
  output wire led1,
  output wire led2,
  output wire led3
);

  // Fixed test vectors
  localparam [127:0] TEST_KEY = 128'h2b7e151628aed2a6abf7158809cf4f3c;
  localparam [127:0] TEST_PT  = 128'h3243f6a8885a308d313198a2e0370734;
  localparam [127:0] FIPS_CT  = 128'h3925841d02dc09fbdc118597196a0b32;

  // Reset logic
  reg [7:0] startup_count = 8'd0;
  reg startup_reset_n = 1'b1;
  reg [1:0] reset_sync = 2'b11;
  wire rst_n;

  always @(posedge clk) begin
    if (startup_count != 8'hff)
      startup_count <= startup_count + 1'b1;
    if (startup_count >= 8'd5 && startup_count <= 8'd10)
      startup_reset_n <= 1'b0;
    else
      startup_reset_n <= 1'b1;
  end

  always @(posedge clk or negedge key0_n) begin
    if (!key0_n)
      reset_sync <= 2'b00;
    else
      reset_sync <= {reset_sync[0], 1'b1};
  end

  assign rst_n = startup_reset_n & reset_sync[1];

  // AES core
  reg core_init = 0;
  reg core_next = 0;
  wire core_ready;
  wire [127:0] core_result;
  wire core_result_valid;

  aes_core_tapped u_aes (
    .clk(clk),
    .reset_n(rst_n),
    .encdec(1'b1),
    .init(core_init),
    .next(core_next),
    .ready(core_ready),
    .key({TEST_KEY, TEST_KEY}),  // Duplicate for 256-bit input
    .keylen(1'b0),  // AES-128
    .block(TEST_PT),
    .result(core_result),
    .result_valid(core_result_valid),
    .round_keys_flat()
  );

  // State machine
  localparam ST_IDLE = 2'd0;
  localparam ST_WAIT_KEY = 2'd1;
  localparam ST_ENCRYPT = 2'd2;
  localparam ST_DONE = 2'd3;

  reg [1:0] state = ST_IDLE;

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state <= ST_IDLE;
      core_init <= 0;
      core_next <= 0;
    end else begin
      core_init <= 0;
      core_next <= 0;

      case (state)
        ST_IDLE: begin
          core_init <= 1;
          state <= ST_WAIT_KEY;
        end

        ST_WAIT_KEY: begin
          if (core_ready) begin
            core_next <= 1;
            state <= ST_ENCRYPT;
          end
        end

        ST_ENCRYPT: begin
          if (core_result_valid) begin
            state <= ST_DONE;
          end
        end

        ST_DONE: begin
          // Done
        end
      endcase
    end
  end

  // LEDs: blink to show state, then show result
  reg [23:0] blink_cnt = 0;
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n)
      blink_cnt <= 0;
    else
      blink_cnt <= blink_cnt + 1;
  end

  // LED0: blink during idle
  assign led0 = (state == ST_IDLE) ? blink_cnt[22] : 1'b0;

  // LED1: blink during wait key
  assign led1 = (state == ST_WAIT_KEY) ? blink_cnt[22] : 1'b0;

  // LED2: blink during encrypt
  assign led2 = (state == ST_ENCRYPT) ? blink_cnt[22] : 1'b0;

  // LED3: ON if result matches FIPS (green), OFF if wrong (red)
  assign led3 = (state == ST_DONE) ? (core_result == FIPS_CT) : 1'b0;

endmodule

`default_nettype wire
