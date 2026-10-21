//---------------------------------------------------------------
// top_demo_debug.v
// Diagnostic-only variant of top_demo.v: identical wiring, but the
// LEDs show uart_cmd_fsm's internal `state` register (3 low bits)
// directly via hierarchical reference, so we can see exactly which
// state it gets stuck in after a command is sent.
//
// State encoding (uart_cmd_fsm.v):
//   0 = ST_IDLE        1 = ST_RECV_CMD     2 = ST_INIT_KEY
//   3 = ST_WAIT_READY   4 = ST_EXEC         5 = ST_SEND_RESP
//   6 = ST_ERR_CHKSUM   7 = ST_EXEC_ACK
//---------------------------------------------------------------
`default_nettype none

module top_demo_debug (
    input  wire       clk,
    input  wire       rst_n,

    input  wire       uart_rx,
    output wire       uart_tx,

    output wire [3:0] led
);

    wire [7:0] rx_data;
    wire       rx_valid;
    wire       rx_ready;

    wire [7:0] tx_data;
    wire       tx_valid;
    wire       tx_ready;

    wire [127:0] cmd_key;
    wire         cmd_key_valid;
    wire         cmd_init;
    wire [127:0] cmd_block;
    wire         cmd_start;
    wire         cmd_done;
    wire         cmd_is_encrypt;

    wire [127:0] aes_result;
    wire         aes_result_valid;
    wire         aes_ready;

    wire [3:0]   muxed_round_nr;
    wire [127:0] state_before_final;

    aes_core_tapped u_aes (
        .clk               (clk),
        .reset_n           (rst_n),

        .encdec            (cmd_is_encrypt),
        .init              (cmd_init),
        .next              (cmd_start),
        .ready             (aes_ready),

        .key               ({128'd0, cmd_key}),
        .keylen            (1'b0),

        .block             (cmd_block),
        .result            (aes_result),
        .result_valid      (aes_result_valid),
        .round_keys_flat   (),

        .muxed_round_nr   (muxed_round_nr),
        .state_before_final(state_before_final)
    );

    uart_rx u_uart_rx (
        .clk           (clk),
        .rst_n         (rst_n),
        .uart_rx       (uart_rx),
        .rx_data       (rx_data),
        .rx_valid      (rx_valid),
        .rx_frame_err  ()
    );

    uart_tx u_uart_tx (
        .clk           (clk),
        .rst_n         (rst_n),
        .tx_data       (tx_data),
        .tx_valid      (tx_valid),
        .uart_tx       (uart_tx),
        .tx_ready      (tx_ready)
    );

    uart_cmd_fsm u_cmd (
        .clk            (clk),
        .rst_n          (rst_n),

        .rx_data        (rx_data),
        .rx_valid       (rx_valid),
        .rx_ready       (rx_ready),

        .tx_data        (tx_data),
        .tx_valid       (tx_valid),
        .tx_ready       (tx_ready),

        .cmd_start      (cmd_start),
        .cmd_init       (cmd_init),
        .cmd_done       (aes_result_valid),
        .aes_ready      (aes_ready),
        .cmd_is_encrypt (cmd_is_encrypt),

        .key            (cmd_key),
        .key_valid      (cmd_key_valid),

        .block          (cmd_block),

        .result         (aes_result),
        .result_ready   ()
    );

    // Debug: show cmd_fsm's state register directly on the LEDs
    // (hierarchical reference - synthesizable for Gowin FPGA flow).
    // LEDs are active-high (led[2]=aes_ready lights when ready=1 in
    // top_demo.v), so a lit LED here means that state bit is 1.
    assign led = u_cmd.state[3:0];

endmodule

//======================================================================
// EOF top_demo_debug.v
//======================================================================
