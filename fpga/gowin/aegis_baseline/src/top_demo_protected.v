//---------------------------------------------------------------
// top_demo_protected.v
// Single AEGIS-protected AES-128 + UART demo
// For fair overhead comparison against baseline aes_core
//---------------------------------------------------------------
`default_nettype none
`include "aegis_defs.vh"

module top_demo_protected (
    input  wire       clk,       // 50MHz system clock
    input  wire       rst_n,     // Active-low reset

    // UART interface
    input  wire       uart_rx,
    output wire       uart_tx,

    // Status LEDs
    output wire [3:0] led
);

    // Internal signals
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

    // AEGIS-AES wrapper signals
    wire         aegis_key_valid;
    wire         aegis_data_valid;
    wire         aegis_busy;
    wire [127:0] aegis_data_out;
    wire         aegis_data_out_valid;
    wire         aegis_sec_alarm;
    wire         aegis_sec_warning;
    wire [7:0]   aegis_sec_status;

    // Map cmd_fsm signals to AEGIS protocol
    assign aegis_key_valid  = cmd_key_valid & cmd_init;
    assign aegis_data_valid = cmd_start & ~aegis_busy;
    assign aes_ready        = ~aegis_busy;
    assign aes_result       = aegis_data_out;
    assign aes_result_valid = aegis_data_out_valid;

    // AEGIS-AES protected core
    aegis_aes_top #(
        .EN_ORC(1)
    ) u_aegis_aes (
        .clk            (clk),
        .rst_n          (rst_n),
        .key            (cmd_key),
        .key_valid      (aegis_key_valid),
        .data_in        (cmd_block),
        .data_in_valid  (aegis_data_valid),
        .data_out       (aegis_data_out),
        .data_out_valid (aegis_data_out_valid),
        .busy           (aegis_busy),
        .sec_alarm      (aegis_sec_alarm),
        .sec_warning    (aegis_sec_warning),
        .sec_status     (aegis_sec_status)
    );

    // UART receiver
    uart_rx u_uart_rx (
        .clk           (clk),
        .rst_n         (rst_n),
        .uart_rx       (uart_rx),
        .rx_data       (rx_data),
        .rx_valid      (rx_valid),
        .rx_frame_err  ()
    );

    // UART transmitter
    uart_tx u_uart_tx (
        .clk           (clk),
        .rst_n         (rst_n),
        .tx_data       (tx_data),
        .tx_valid      (tx_valid),
        .uart_tx       (uart_tx),
        .tx_ready      (tx_ready)
    );

    // Command FSM (reuse from baseline)
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

    // Status LEDs
    assign led[0] = ~uart_rx;           // RX activity
    assign led[1] = ~uart_tx;           // TX activity
    assign led[2] = aes_ready;          // AEGIS idle
    assign led[3] = aegis_sec_alarm;    // Security alarm

endmodule

//======================================================================
// EOF top_demo_protected.v
//======================================================================
