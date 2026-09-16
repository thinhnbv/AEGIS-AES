//======================================================================
// uart_echo.v
// UART Echo - echoes any received byte
//======================================================================
`default_nettype none

module uart_echo (
    input  wire clk,
    input  wire rst_n,
    input  wire uart_rx,
    output wire uart_tx,
    output reg  led
);

    wire [7:0] rx_data;
    wire rx_valid;
    wire tx_busy;
    reg tx_start;
    reg [7:0] tx_data;

    // UART Receiver
    uart_rx_core rx (
        .clk(clk),
        .rst_n(rst_n),
        .rx_serial(uart_rx),
        .rx_data(rx_data),
        .rx_valid(rx_valid),
        .rx_error()
    );

    // UART Transmitter
    uart_tx_core tx (
        .clk(clk),
        .rst_n(rst_n),
        .tx_data(tx_data),
        .tx_start(tx_start),
        .tx_serial(uart_tx),
        .tx_busy(tx_busy)
    );

    // Echo logic - echo any received byte
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            tx_start <= 1'b0;
            tx_data <= 8'h00;
            led <= 1'b0;
        end else begin
            tx_start <= 1'b0;

            if (rx_valid && !tx_busy) begin
                tx_data <= rx_data;
                tx_start <= 1'b1;
                led <= 1'b1;
            end else begin
                led <= 1'b0;
            end
        end
    end

endmodule
