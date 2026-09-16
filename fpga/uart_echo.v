//---------------------------------------------------------------
// uart_echo.v
// Complete UART echo - LED on when 'A' received, send 'X'
//---------------------------------------------------------------
`default_nettype none

module uart_echo (
    input  wire clk,
    input  wire rst_n,
    input  wire uart_rx,
    output reg  uart_tx,
    output reg  led
);

    // RX
    reg [7:0] rx_byte;
    reg rx_done;

    // TX
    reg [7:0] tx_byte;
    reg tx_start;
    reg [4:0] tx_bit_cnt;
    reg [15:0] tx_baud_cnt;
    localparam BAUD = 16'd434;

    // FSM
    reg [2:0] state;
    localparam RX_IDLE = 3'd0;
    localparam RX_DATA = 3'd1;
    localparam TX_IDLE = 3'd2;
    localparam TX_START = 3'd3;
    localparam TX_DATA = 3'd4;
    localparam TX_STOP = 3'd5;

    // RX state
    reg [4:0] rx_bit_cnt;
    reg [15:0] rx_baud_cnt;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= RX_IDLE;
            rx_byte <= 8'h00;
            rx_done <= 1'b0;
            rx_bit_cnt <= 5'd0;
            rx_baud_cnt <= 16'd0;
            tx_byte <= 8'h58;  // 'X'
            tx_start <= 1'b0;
            tx_bit_cnt <= 5'd0;
            tx_baud_cnt <= 16'd0;
            uart_tx <= 1'b1;
            led <= 1'b0;
        end else begin
            tx_start <= 1'b0;

            case (state)
                // Receive
                RX_IDLE: begin
                    led <= 1'b0;
                    rx_bit_cnt <= 5'd0;
                    rx_baud_cnt <= 16'd0;
                    if (uart_rx == 1'b0) begin
                        state <= RX_DATA;
                    end
                end

                RX_DATA: begin
                    rx_baud_cnt <= rx_baud_cnt + 1'b1;
                    if (rx_baud_cnt >= BAUD - 1) begin
                        rx_baud_cnt <= 16'd0;
                        rx_bit_cnt <= rx_bit_cnt + 1'b1;
                        if (rx_bit_cnt >= 5'd1 && rx_bit_cnt <= 5'd8) begin
                            rx_byte[rx_bit_cnt - 1] <= uart_rx;
                        end
                        if (rx_bit_cnt == 5'd9) begin
                            rx_done <= 1'b1;
                            if (rx_byte == 8'h41) begin  // 'A'
                                led <= 1'b1;
                                tx_start <= 1'b1;
                            end
                            state <= TX_IDLE;
                        end
                    end
                end

                // Transmit
                TX_IDLE: begin
                    if (tx_start) begin
                        tx_bit_cnt <= 5'd0;
                        tx_baud_cnt <= 16'd0;
                        state <= TX_START;
                    end
                end

                TX_START: begin
                    uart_tx <= 1'b0;  // Start bit
                    tx_baud_cnt <= tx_baud_cnt + 1'b1;
                    if (tx_baud_cnt >= BAUD - 1) begin
                        tx_baud_cnt <= 16'd0;
                        tx_bit_cnt <= tx_bit_cnt + 1'b1;
                        state <= TX_DATA;
                    end
                end

                TX_DATA: begin
                    tx_baud_cnt <= tx_baud_cnt + 1'b1;
                    if (tx_baud_cnt >= BAUD - 1) begin
                        tx_baud_cnt <= 16'd0;
                        tx_bit_cnt <= tx_bit_cnt + 1'b1;
                        if (tx_bit_cnt <= 5'd7) begin
                            uart_tx <= tx_byte[tx_bit_cnt];
                        end
                        if (tx_bit_cnt == 5'd8) begin
                            uart_tx <= 1'b1;  // Stop bit
                        end
                        if (tx_bit_cnt == 5'd9) begin
                            state <= TX_STOP;
                        end
                    end
                end

                TX_STOP: begin
                    uart_tx <= 1'b1;
                    tx_baud_cnt <= tx_baud_cnt + 1'b1;
                    if (tx_baud_cnt >= BAUD - 1) begin
                        rx_done <= 1'b0;
                        state <= RX_IDLE;
                    end
                end
            endcase
        end
    end

endmodule
