// ============================================================================
// Project     : AEGIS-AES
// Module      : top_demo
// Description : FPGA top-level for the Gowin ACG525 UART demonstration.
// ============================================================================

`default_nettype none

module top_demo #(
  parameter [15:0] CLKS_PER_BIT = 16'd434,
  parameter [31:0] INTERBYTE_TIMEOUT_CLKS = 32'd500000,
  parameter LED_ACTIVE_LOW = 1'b0
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

  //----------------------------------------------------------------
  // Startup reset and KEY0 reset synchronizer.
  //
  // Gowin fabric receives an explicit reset pulse after the input
  // clock is already running. This makes power-up independent of
  // whether KEY0 was pressed while the SRAM bitstream was loaded.
  //
  // key0_n low:
  //   - reset is asserted asynchronously.
  //
  // key0_n high:
  //   - reset is deasserted after two clk rising edges.
  //----------------------------------------------------------------
  localparam [7:0] STARTUP_RESET_BEGIN = 8'd5;
  localparam [7:0] STARTUP_RESET_END   = 8'd10;

  reg [7:0] startup_count_reg = 8'd0;
  reg       startup_reset_n_reg = 1'b1;
  reg [1:0] reset_sync_reg;

  always @(posedge clk) begin
    if (startup_count_reg != 8'hff)
      startup_count_reg <= startup_count_reg + 1'b1;

    if ((startup_count_reg >= STARTUP_RESET_BEGIN) &&
        (startup_count_reg <= STARTUP_RESET_END))
      startup_reset_n_reg <= 1'b0;
    else
      startup_reset_n_reg <= 1'b1;
  end

  always @(posedge clk or negedge key0_n) begin
    if (!key0_n)
      reset_sync_reg <= 2'b00;
    else
      reset_sync_reg <= {reset_sync_reg[0], 1'b1};
  end

  wire rst_n;
  assign rst_n = startup_reset_n_reg & reset_sync_reg[1];

  //----------------------------------------------------------------
  // UART RX PHY.
  //----------------------------------------------------------------
  wire [7:0] uart_rx_data;
  wire       uart_rx_valid;
  wire       uart_rx_frame_error;

  uart_rx #(
    .CLKS_PER_BIT(CLKS_PER_BIT)
  ) u_uart_rx (
    .clk(clk),
    .rst_n(rst_n),

    .rx(uart_rx),

    .rx_data(uart_rx_data),
    .rx_valid(uart_rx_valid),
    .frame_error(uart_rx_frame_error)
  );

  //----------------------------------------------------------------
  // UART TX PHY.
  //----------------------------------------------------------------
  wire [7:0] uart_tx_data;
  wire       uart_tx_start;
  wire       uart_tx_busy;
  wire       uart_tx_done;

  uart_tx #(
    .CLKS_PER_BIT(CLKS_PER_BIT)
  ) u_uart_tx (
    .clk(clk),
    .rst_n(rst_n),

    .tx_start(uart_tx_start),
    .tx_data(uart_tx_data),

    .tx(uart_tx),
    .tx_busy(uart_tx_busy),
    .tx_done(uart_tx_done)
  );

  //----------------------------------------------------------------
  // Demo core system.
  //----------------------------------------------------------------
  wire       sec_alarm_internal;

  /* verilator lint_off UNUSEDSIGNAL */
  wire       controller_busy;
  wire [7:0] sec_status_internal;
  /* verilator lint_on UNUSEDSIGNAL */

  wire clean_match_event;
  wire raw_key_leak_event;
  wire protocol_error_event;

  demo_core_system #(
    .INTERBYTE_TIMEOUT_CLKS(INTERBYTE_TIMEOUT_CLKS)
  ) u_demo_core_system (
    .clk(clk),
    .rst_n(rst_n),

    .rx_data(uart_rx_data),
    .rx_valid(uart_rx_valid),
    .rx_frame_error(uart_rx_frame_error),

    .tx_data(uart_tx_data),
    .tx_start(uart_tx_start),
    .tx_busy(uart_tx_busy),
    .tx_done(uart_tx_done),

    .controller_busy(controller_busy),
    .sec_alarm(sec_alarm_internal),
    .sec_status(sec_status_internal),

    .clean_match_event(clean_match_event),
    .raw_key_leak_event(raw_key_leak_event),
    .protocol_error_event(protocol_error_event)
  );

  //----------------------------------------------------------------
  // Sticky LED status.
  //----------------------------------------------------------------
  reg clean_seen_reg;
  reg raw_leak_seen_reg;
  reg uart_error_seen_reg;

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      clean_seen_reg <= 1'b0;
      raw_leak_seen_reg <= 1'b0;
      uart_error_seen_reg <= 1'b0;
    end else begin
      if (clean_match_event)
        clean_seen_reg <= 1'b1;

      if (raw_key_leak_event)
        raw_leak_seen_reg <= 1'b1;

      if (protocol_error_event)
        uart_error_seen_reg <= 1'b1;
    end
  end

  //----------------------------------------------------------------
  // Physical LED polarity.
  //
  // LED0: clean raw/protected outputs matched.
  // LED1: raw T01 key leak observed.
  // LED2: protected AEGIS security alarm.
  // LED3: UART frame/protocol error observed.
  //----------------------------------------------------------------
  assign led0 =
    LED_ACTIVE_LOW ? !clean_seen_reg : clean_seen_reg;

  assign led1 =
    LED_ACTIVE_LOW ? !raw_leak_seen_reg : raw_leak_seen_reg;

  assign led2 =
    LED_ACTIVE_LOW ? !sec_alarm_internal : sec_alarm_internal;

  assign led3 =
    LED_ACTIVE_LOW ? !uart_error_seen_reg : uart_error_seen_reg;

endmodule

`default_nettype wire
