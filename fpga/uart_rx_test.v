//---------------------------------------------------------------
// uart_rx_test.v
// UART RX test - LED on when start bit detected
//---------------------------------------------------------------
`default_nettype none

module uart_rx_test (
    input  wire clk,
    input  wire rst_n,
    input  wire uart_rx,
    output reg  led
);

    // Simple: LED on when start bit (uart_rx = 0)
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            led <= 1'b0;
        end else begin
            led <= ~uart_rx;  // LED on when receiving (start bit = 0)
        end
    end

endmodule
