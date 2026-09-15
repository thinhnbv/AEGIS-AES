//---------------------------------------------------------------
// uart_echo.v
// Simple UART echo test - echoes received bytes back
//---------------------------------------------------------------
`default_nettype none

module uart_echo (
    input  wire clk,
    input  wire rst_n,
    input  wire uart_rx,
    output wire uart_tx,
    output wire [3:0] led
);

    wire [7:0] rx_data;
    wire rx_valid;

    wire [7:0] tx_data;
    wire tx_valid;
    wire tx_ready;

    // UART receiver
    uart_rx uart_rx_inst (
        .clk(clk),
        .rst_n(rst_n),
        .uart_rx(uart_rx),
        .rx_data(rx_data),
        .rx_valid(rx_valid),
        .rx_frame_err()
    );

    // UART transmitter
    uart_tx uart_tx_inst (
        .clk(clk),
        .rst_n(rst_n),
        .tx_data(rx_data),  // Echo received data
        .tx_valid(tx_valid),
        .uart_tx(uart_tx),
        .tx_ready(tx_ready)
    );

    // Echo enable logic
    reg tx_valid_reg;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            tx_valid_reg <= 1'b0;
        end else begin
            tx_valid_reg <= rx_valid && tx_ready;
        end
    end
    assign tx_valid = tx_valid_reg;

    // LED indicators
    assign led[0] = rx_valid;   // Flash on receive
    assign led[1] = tx_valid;   // Flash on transmit
    assign led[2] = 1'b1;       // Always on
    assign led[3] = 1'b0;

endmodule
