//---------------------------------------------------------------
// uart_rx_only.v
// UART RX only test - LED on when 'A' received
//---------------------------------------------------------------
`default_nettype none

module uart_rx_only (
    input  wire clk,
    input  wire rst_n,
    input  wire uart_rx,
    output reg  led
);

    reg [3:0] state;
    localparam IDLE = 4'd0;
    localparam RECEIVE = 4'd1;

    reg [3:0] bit_cnt;
    reg [7:0] rx_data;
    reg [15:0] baud_cnt;
    localparam BAUD = 16'd434;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            led <= 1'b0;
            bit_cnt <= 4'd0;
            rx_data <= 8'h00;
            baud_cnt <= 16'd0;
        end else begin
            case (state)
                IDLE: begin
                    led <= 1'b0;
                    if (uart_rx == 1'b0) begin  // Start bit
                        state <= RECEIVE;
                        bit_cnt <= 4'd0;
                        baud_cnt <= 16'd0;
                    end
                end

                RECEIVE: begin
                    baud_cnt <= baud_cnt + 1'b1;

                    if (baud_cnt >= BAUD - 1) begin
                        baud_cnt <= 16'd0;
                        bit_cnt <= bit_cnt + 1'b1;

                        // Sample data bits
                        if (bit_cnt >= 4'd1 && bit_cnt <= 4'd8) begin
                            rx_data[bit_cnt - 1] <= uart_rx;
                        end

                        // Check if 'A' received
                        if (bit_cnt == 4'd9) begin
                            if (rx_data == 8'h41) begin  // 'A'
                                led <= 1'b1;
                            end
                            state <= IDLE;
                        end
                    end
                end
            endcase
        end
    end

endmodule
