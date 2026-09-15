//---------------------------------------------------------------
// led_test.v
// Simple LED blinking test for ACG525 board
//---------------------------------------------------------------
`default_nettype none

module led_test (
    input  wire clk,
    input  wire rst_n,
    output wire [3:0] led
);

    reg [25:0] counter;
    reg blink;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            counter <= 26'd0;
            blink <= 1'b0;
        end else begin
            counter <= counter + 1'b1;
            if (counter == 26'd0) begin
                blink <= ~blink;
            end
        end
    end

    assign led[0] = blink;      // LED0 blinks
    assign led[1] = ~blink;    // LED1 blinks opposite
    assign led[2] = 1'b1;      // LED2 always on
    assign led[3] = 1'b0;      // LED3 always off

endmodule
