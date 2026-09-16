//---------------------------------------------------------------
// uart_echo_simple.v
// Simple UART Echo - LED on when byte received, send 'X' on TX
//---------------------------------------------------------------
`default_nettype none

module uart_echo_simple (
    input  wire clk,
    input  wire rst_n,
    input  wire uart_rx,
    output reg  uart_tx,
    output reg  led
);

    // State
    reg [3:0] state;
    localparam RX_IDLE = 4'd0;
    localparam RX_WAIT = 4'd1;
    localparam TX_SEND = 4'd2;

    // RX signals
    reg [3:0] rx_bit_cnt;
    reg [7:0] rx_data;
    reg [15:0] rx_baud_cnt;
    localparam BAUD_MAX = 16'd434;

    // TX signals
    reg [3:0] tx_bit_cnt;
    reg [7:0] tx_data;
    reg [15:0] tx_baud_cnt;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= RX_IDLE;
            uart_tx <= 1'b1;
            led <= 1'b0;
            rx_bit_cnt <= 4'd0;
            rx_baud_cnt <= 16'd0;
            rx_data <= 8'h00;
            tx_bit_cnt <= 4'd0;
            tx_baud_cnt <= 16'd0;
            tx_data <= 8'h58;  // 'X'
        end else begin
            case (state)
                // Wait for start bit
                RX_IDLE: begin
                    led <= 1'b0;
                    if (uart_rx == 1'b0) begin
                        state <= RX_WAIT;
                        rx_bit_cnt <= 4'd0;
                        rx_baud_cnt <= 16'd0;
                    end
                end

                // Receive data bits
                RX_WAIT: begin
                    rx_baud_cnt <= rx_baud_cnt + 1'b1;

                    if (rx_baud_cnt >= BAUD_MAX - 1) begin
                        rx_baud_cnt <= 16'd0;
                        rx_bit_cnt <= rx_bit_cnt + 1'b1;

                        // Sample at middle of bit
                        if (rx_bit_cnt >= 4'd1 && rx_bit_cnt <= 4'd8) begin
                            rx_data[rx_bit_cnt - 1] <= uart_rx;
                        end

                        // Done receiving
                        if (rx_bit_cnt == 4'd9) begin
                            led <= 1'b1;
                            state <= TX_SEND;
                            tx_bit_cnt <= 4'd0;
                            tx_baud_cnt <= 16'd0;
                        end
                    end
                end

                // Transmit 'X'
                TX_SEND: begin
                    tx_baud_cnt <= tx_baud_cnt + 1'b1;

                    if (tx_baud_cnt >= BAUD_MAX - 1) begin
                        tx_baud_cnt <= 16'd0;
                        tx_bit_cnt <= tx_bit_cnt + 1'b1;

                        // Send bits
                        if (tx_bit_cnt == 4'd0) uart_tx <= 1'b0;  // Start
                        else if (tx_bit_cnt == 4'd1) uart_tx <= tx_data[0];
                        else if (tx_bit_cnt == 4'd2) uart_tx <= tx_data[1];
                        else if (tx_bit_cnt == 4'd3) uart_tx <= tx_data[2];
                        else if (tx_bit_cnt == 4'd4) uart_tx <= tx_data[3];
                        else if (tx_bit_cnt == 4'd5) uart_tx <= tx_data[4];
                        else if (tx_bit_cnt == 4'd6) uart_tx <= tx_data[5];
                        else if (tx_bit_cnt == 4'd7) uart_tx <= tx_data[6];
                        else if (tx_bit_cnt == 4'd8) uart_tx <= tx_data[7];
                        else if (tx_bit_cnt == 4'd9) uart_tx <= 1'b1;  // Stop
                        else begin
                            uart_tx <= 1'b1;
                            state <= RX_IDLE;
                        end
                    end
                end
            endcase
        end
    end

endmodule
