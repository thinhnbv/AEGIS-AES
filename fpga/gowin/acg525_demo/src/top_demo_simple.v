// ============================================================================
// Project     : AEGIS-AES
// Module      : top_demo_simple
// Description : Minimal test - just AES encryption with fixed key/plaintext.
//               Results sent via UART. Debug LEDs show status.
// ============================================================================

`default_nettype none

module top_demo_simple #(
  parameter [15:0] CLKS_PER_BIT = 16'd434
) (
  input  wire clk,
  input  wire key0_n,
  input  wire uart_rx,

  output wire uart_tx,

  output wire led0,
  output wire led1,
  output wire led2,
  output wire led3
);

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

  // UART RX
  wire [7:0] rx_data;
  wire rx_valid;
  wire rx_frame_error;

  uart_rx #(.CLKS_PER_BIT(CLKS_PER_BIT)) uart_rx_inst (
    .clk(clk), .rst_n(rst_n), .rx(uart_rx),
    .rx_data(rx_data), .rx_valid(rx_valid), .frame_error(rx_frame_error)
  );

  // UART TX
  wire [7:0] tx_data;
  wire tx_start;
  wire tx_busy;
  wire tx_done;

  uart_tx #(.CLKS_PER_BIT(CLKS_PER_BIT)) uart_tx_inst (
    .clk(clk), .rst_n(rst_n), .tx_start(tx_start), .tx_data(tx_data),
    .tx(uart_tx), .tx_busy(tx_busy), .tx_done(tx_done)
  );

  // AES core signals
  reg core_init = 0;
  reg core_next = 0;
  wire core_ready;
  wire [127:0] core_result;
  wire core_result_valid;
  wire [1407:0] round_keys_flat;

  // AES core instantiation
  aes_core_tapped aes_core_inst (
    .clk(clk),
    .reset_n(rst_n),
    .encdec(1'b1),
    .init(core_init),
    .next(core_next),
    .ready(core_ready),
    .key({128'h2b7e151628aed2a6abf7158809cf4f3c,
          128'h2b7e151628aed2a6abf7158809cf4f3c}),
    .keylen(1'b0),
    .block(128'h3243f6a8885a308d313198a2e0370734),
    .result(core_result),
    .result_valid(core_result_valid),
    .round_keys_flat(round_keys_flat)
  );

  // State machine
  localparam ST_IDLE = 3'd0;
  localparam ST_WAIT_KEY = 3'd1;
  localparam ST_ENCRYPT = 3'd2;
  localparam ST_SEND_RESULT = 3'd3;

  reg [2:0] state = ST_IDLE;
  reg [127:0] result_reg = 0;

  // Blink LED0 to show system is alive
  reg [23:0] blink_cnt = 0;
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n)
      blink_cnt <= 0;
    else
      blink_cnt <= blink_cnt + 1;
  end
  assign led0 = blink_cnt[23];  // Blink ~1.5Hz

  // Main FSM
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state <= ST_IDLE;
      core_init <= 0;
      core_next <= 0;
      result_reg <= 0;
    end else begin
      core_init <= 0;
      core_next <= 0;

      case (state)
        ST_IDLE: begin
          // Auto-start encryption after reset
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
            result_reg <= core_result;
            state <= ST_SEND_RESULT;
          end
        end

        ST_SEND_RESULT: begin
          // Stay here, result available in result_reg
          // LED1 shows result is available
          if (result_reg == 128'h3925841d02dc09fbdc118597196a0b32)
            led1 <= 1;  // Green = correct FIPS result
          else
            led2 <= 1;  // Red = wrong result
        end
      endcase
    end
  end

  assign led1 = 1'b0;
  assign led2 = 1'b0;
  assign led3 = 1'b0;

endmodule

`default_nettype wire
