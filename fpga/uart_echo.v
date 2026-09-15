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

    reg [7:0] rx_data;
    reg rx_valid;
    wire rx_ready;

    reg [7:0] tx_data;
    reg tx_valid;
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
        .tx_data(tx_data),
        .tx_valid(tx_valid),
        .uart_tx(uart_tx),
        .tx_ready(tx_ready)
    );

    // Echo logic
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            tx_valid <= 1'b0;
            tx_data <= 8'h00;
        end else begin
            if (rx_valid && tx_ready) begin
                tx_data <= rx_data;
                tx_valid <= 1'b1;
            end else begin
                tx_valid <= 1'b0;
            end
        end
    end

    // LED indicators
    assign led[0] = rx_valid;   // Flash on receive
    assign led[1] = tx_valid;   // Flash on transmit
    assign led[2] = 1'b1;       // Always on
    assign led[3] = 1'b0;

endmodule
