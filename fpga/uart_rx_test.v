//---------------------------------------------------------------
// uart_rx_test.v
// Simple UART receiver test - LED toggles when receiving
//---------------------------------------------------------------
`default_nettype none

module uart_rx_test (
    input  wire clk,
    input  wire rst_n,
    input  wire uart_rx,
    output reg  led
);

    // Detect falling edge (start bit)
    reg uart_rx_prev;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            led <= 1'b0;
            uart_rx_prev <= 1'b1;
        end else begin
            // Toggle LED on falling edge (start bit detected)
            if (uart_rx_prev == 1'b1 && uart_rx == 1'b0) begin
                led <= ~led;
            end
            uart_rx_prev <= uart_rx;
        end
    end

endmodule
