//---------------------------------------------------------------
// uart_rx_test.v
// UART receiver test - LED turns ON when receiving data
//---------------------------------------------------------------
`default_nettype none

module uart_rx_test (
    input  wire clk,
    input  wire rst_n,
    input  wire uart_rx,
    output reg  led
);

    // Counter for LED pulse duration
    reg [23:0] counter;
    parameter PULSE_CYCLES = 24'd12_500_000;  // ~0.25 second at 50MHz

    // Detect falling edge (start bit)
    reg uart_rx_prev;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            led <= 1'b0;
            counter <= 24'd0;
            uart_rx_prev <= 1'b1;
        end else begin
            uart_rx_prev <= uart_rx;

            // Counter logic
            if (counter > 24'd0) begin
                counter <= counter - 1'b1;
                led <= 1'b1;  // LED ON during counter
            end else begin
                led <= 1'b0;

                // Detect start bit (falling edge)
                if (uart_rx_prev == 1'b1 && uart_rx == 1'b0) begin
                    counter <= PULSE_CYCLES;  // Start LED pulse
                end
            end
        end
    end

endmodule
