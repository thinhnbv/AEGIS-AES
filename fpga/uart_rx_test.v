//---------------------------------------------------------------
// uart_rx_test.v
// Simple UART receiver test - LED on when receiving
//---------------------------------------------------------------
`default_nettype none

module uart_rx_test (
    input  wire clk,
    input  wire rst_n,
    input  wire uart_rx,
    output wire led
);

    // Simple: LED on when uart_rx is LOW (start bit)
    // This bypasses the uart_rx module for testing
    assign led = ~uart_rx;  // LED on when receiving (uart_rx=0)

endmodule
