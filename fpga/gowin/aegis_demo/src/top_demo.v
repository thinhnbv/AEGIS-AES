//---------------------------------------------------------------
// top_demo.v
// Top-level module for AEGIS-AES FPGA Demo
// ACG525 board with GW5A-25 FPGA
//---------------------------------------------------------------
`default_nettype none

module top_demo (
    input  wire       clk,       // 50MHz system clock
    input  wire       rst_n,    // Active-low reset

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

    wire [3:0]   muxed_round_nr;
    wire [127:0] state_before_final;

    // AES core instance
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

    // Command FSM
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
    assign led[2] = aes_ready;          // AES idle
    assign led[3] = muxed_round_nr[0]; // Round LSB (debug)

endmodule

//======================================================================
// EOF top_demo.v
//======================================================================
