// ============================================================================
// Project     : AEGIS-AES
// Module      : demo_core_system
// Description : Integrate byte-level UART framing, demo controller,
//               raw AES path, and protected AEGIS-AES path.
// ============================================================================

`default_nettype none

module demo_core_system #(
  parameter [31:0] INTERBYTE_TIMEOUT_CLKS = 32'd500000
) (
  input  wire       clk,
  input  wire       rst_n,

  // Byte-level input from uart_rx.
  input  wire [7:0] rx_data,
  input  wire       rx_valid,
  input  wire       rx_frame_error,

  // Byte-level output to uart_tx.
  output wire [7:0] tx_data,
  output wire       tx_start,
  input  wire       tx_busy,
  input  wire       tx_done,

  // Status for top-level and LEDs.
  output wire       controller_busy,
  output wire       sec_alarm,
  output wire [7:0] sec_status,

  // One-clock demo events.
  output wire       clean_match_event,
  output wire       raw_key_leak_event,
  output wire       protocol_error_event
);

  //----------------------------------------------------------------
  // Request parser signals.
  //----------------------------------------------------------------
  // Parser busy is currently kept for internal observability only.
  /* verilator lint_off UNUSEDSIGNAL */
  wire frame_busy;
  /* verilator lint_on UNUSEDSIGNAL */
  wire         req_valid;
  wire         req_error_valid;
  wire [7:0]   req_seq;
  wire [127:0] req_key;
  wire [127:0] req_plaintext;

  //----------------------------------------------------------------
  // Shared controller-to-core request.
  //----------------------------------------------------------------
  wire [127:0] core_key;
  wire [127:0] core_data_in;

  //----------------------------------------------------------------
  // Raw AES path.
  //----------------------------------------------------------------
  wire         raw_key_valid;
  wire         raw_data_in_valid;
  wire         raw_busy;
  wire [127:0] raw_data_out;
  wire         raw_data_out_valid;

  //----------------------------------------------------------------
  // Protected AEGIS path.
  //----------------------------------------------------------------
  wire         protected_key_valid;
  wire         protected_data_in_valid;
  wire         protected_busy;
  wire [127:0] protected_data_out;
  wire         protected_data_out_valid;
  wire         protected_sec_alarm;
  wire [7:0]   protected_sec_status;

  // The current prototype does not use sec_warning in the FPGA demo.
  /* verilator lint_off UNUSEDSIGNAL */
  wire protected_sec_warning;
  /* verilator lint_on UNUSEDSIGNAL */

  //----------------------------------------------------------------
  // Controller-to-response serializer.
  //----------------------------------------------------------------
  wire         controller_rsp_start;
  wire [7:0]   controller_rsp_seq;
  wire [7:0]   controller_rsp_flags;
  wire [7:0]   controller_rsp_status;
  wire [127:0] controller_rsp_raw;
  wire [127:0] controller_rsp_protected;

  wire frame_tx_busy;
  // The controller tracks frame_tx_busy; frame_tx_done is not required.
  /* verilator lint_off UNUSEDSIGNAL */
  wire frame_tx_done;
  /* verilator lint_on UNUSEDSIGNAL */

  //----------------------------------------------------------------
  // Request frame parser.
  //----------------------------------------------------------------
  uart_frame_rx #(
    .INTERBYTE_TIMEOUT_CLKS(INTERBYTE_TIMEOUT_CLKS)
  ) u_frame_rx (
    .clk(clk),
    .rst_n(rst_n),

    .rx_data(rx_data),
    .rx_valid(rx_valid),
    .rx_frame_error(rx_frame_error),

    .frame_busy(frame_busy),
    .req_valid(req_valid),
    .req_error_valid(req_error_valid),
    .req_seq(req_seq),
    .req_key(req_key),
    .req_plaintext(req_plaintext)
  );

  //----------------------------------------------------------------
  // Raw AES adapter.
  //----------------------------------------------------------------
  raw_aes_adapter u_raw (
    .clk(clk),
    .rst_n(rst_n),

    .key(core_key),
    .key_valid(raw_key_valid),

    .data_in(core_data_in),
    .data_in_valid(raw_data_in_valid),

    .data_out(raw_data_out),
    .data_out_valid(raw_data_out_valid),
    .busy(raw_busy)
  );

  //----------------------------------------------------------------
  // Protected AEGIS-AES path.
  //----------------------------------------------------------------
  aegis_aes_top u_protected (
    .clk(clk),
    .rst_n(rst_n),

    .key(core_key),
    .key_valid(protected_key_valid),

    .data_in(core_data_in),
    .data_in_valid(protected_data_in_valid),

    .data_out(protected_data_out),
    .data_out_valid(protected_data_out_valid),
    .busy(protected_busy),

    .sec_alarm(protected_sec_alarm),
    .sec_warning(protected_sec_warning),
    .sec_status(protected_sec_status)
  );

  //----------------------------------------------------------------
  // Dual-core demo controller.
  //----------------------------------------------------------------
  demo_controller u_controller (
    .clk(clk),
    .rst_n(rst_n),

    .req_valid(req_valid),
    .req_error_valid(req_error_valid),
    .req_seq(req_seq),
    .req_key(req_key),
    .req_plaintext(req_plaintext),

    .core_key(core_key),
    .core_data_in(core_data_in),

    .raw_key_valid(raw_key_valid),
    .raw_data_in_valid(raw_data_in_valid),
    .raw_busy(raw_busy),
    .raw_data_out(raw_data_out),
    .raw_data_out_valid(raw_data_out_valid),

    .protected_key_valid(protected_key_valid),
    .protected_data_in_valid(protected_data_in_valid),
    .protected_busy(protected_busy),
    .protected_data_out(protected_data_out),
    .protected_data_out_valid(protected_data_out_valid),
    .protected_sec_alarm(protected_sec_alarm),
    .protected_sec_status(protected_sec_status),

    .rsp_busy(frame_tx_busy),
    .rsp_start(controller_rsp_start),
    .rsp_seq(controller_rsp_seq),
    .rsp_flags(controller_rsp_flags),
    .rsp_sec_status(controller_rsp_status),
    .rsp_raw_out(controller_rsp_raw),
    .rsp_protected_out(controller_rsp_protected),

    .controller_busy(controller_busy)
  );

  //----------------------------------------------------------------
  // Response frame serializer.
  //----------------------------------------------------------------
  uart_frame_tx u_frame_tx (
    .clk(clk),
    .rst_n(rst_n),

    .rsp_start(controller_rsp_start),
    .rsp_seq(controller_rsp_seq),
    .rsp_flags(controller_rsp_flags),
    .rsp_sec_status(controller_rsp_status),
    .rsp_raw_out(controller_rsp_raw),
    .rsp_protected_out(controller_rsp_protected),

    .rsp_busy(frame_tx_busy),
    .rsp_done(frame_tx_done),

    .tx_data(tx_data),
    .tx_start(tx_start),
    .tx_busy(tx_busy),
    .tx_done(tx_done)
  );

  //----------------------------------------------------------------
  // Demo event generation.
  //
  // All source signals are registered, and controller_rsp_start is
  // a one-clock pulse. Therefore these outputs are also one-clock
  // events without additional state.
  //----------------------------------------------------------------

  // Clean result: both outputs valid, no alarm, and both match.
  assign clean_match_event =
    controller_rsp_start &&
    (controller_rsp_flags[1:0] == 2'b11) &&
    !controller_rsp_flags[2] &&
    (controller_rsp_raw == controller_rsp_protected);

  // T01 observation: raw output equals the request key while the
  // protected path reports alarm and blocked output.
  assign raw_key_leak_event =
    controller_rsp_start &&
    controller_rsp_flags[0] &&
    controller_rsp_flags[2] &&
    controller_rsp_flags[3] &&
    (controller_rsp_raw == core_key);

  // Parser errors never activate either AES path.
  assign protocol_error_event = req_error_valid;

  //----------------------------------------------------------------
  // Security status mapping.
  //----------------------------------------------------------------
  assign sec_alarm = protected_sec_alarm;
  assign sec_status = protected_sec_status;

endmodule

`default_nettype wire
