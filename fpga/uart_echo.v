//---------------------------------------------------------------
// uart_echo.v
// UART RX + TX - send 'X' when 'A' received
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
    reg [3:0] rx_state;
    reg [3:0] rx_bit_cnt;
    reg [7:0] rx_data;
    reg [15:0] rx_baud_cnt;
    localparam RX_IDLE = 4'd0;
    localparam RX_DATA = 4'd1;
    localparam RX_DONE = 4'd2;

    // TX
    reg [3:0] tx_state;
    reg [3:0] tx_bit_cnt;
    reg [15:0] tx_baud_cnt;
    localparam TX_IDLE = 4'd0;
    localparam TX_DATA = 4'd1;
    localparam TX_DONE = 4'd2;
    localparam BAUD = 16'd434;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            rx_state <= RX_IDLE;
            rx_bit_cnt <= 4'd0;
            rx_data <= 8'h00;
            rx_baud_cnt <= 16'd0;

            tx_state <= TX_IDLE;
            tx_bit_cnt <= 4'd0;
            tx_baud_cnt <= 16'd0;
            uart_tx <= 1'b1;
            led <= 1'b0;
        end else begin
            // RX
            case (rx_state)
                RX_IDLE: begin
                    rx_bit_cnt <= 4'd0;
                    rx_baud_cnt <= 16'd0;
                    if (uart_rx == 1'b0) begin
                        rx_state <= RX_DATA;
                    end
                end

                RX_DATA: begin
                    rx_baud_cnt <= rx_baud_cnt + 1'b1;
                    if (rx_baud_cnt >= BAUD - 1) begin
                        rx_baud_cnt <= 16'd0;
                        rx_bit_cnt <= rx_bit_cnt + 1'b1;
                        if (rx_bit_cnt >= 4'd1 && rx_bit_cnt <= 4'd8) begin
                            rx_data[rx_bit_cnt - 1] <= uart_rx;
                        end
                        if (rx_bit_cnt == 4'd9) begin
                            rx_state <= RX_DONE;
                        end
                    end
                end

                RX_DONE: begin
                    rx_state <= RX_IDLE;
                end
            endcase

            // TX - only start when 'A' received
            case (tx_state)
                TX_IDLE: begin
                    tx_bit_cnt <= 4'd0;
                    tx_baud_cnt <= 16'd0;
                    uart_tx <= 1'b1;
                    if (rx_state == RX_DONE && rx_data == 8'h41) begin  // 'A'
                        led <= 1'b1;
                        tx_state <= TX_DATA;
                    end else begin
                        led <= 1'b0;
                    end
                end

                TX_DATA: begin
                    led <= 1'b1;
                    tx_baud_cnt <= tx_baud_cnt + 1'b1;
                    if (tx_baud_cnt >= BAUD - 1) begin
                        tx_baud_cnt <= 16'd0;
                        tx_bit_cnt <= tx_bit_cnt + 1'b1;

                        // Send 'X' = 0x58
                        if (tx_bit_cnt == 4'd0) uart_tx <= 1'b0;  // Start
                        else if (tx_bit_cnt == 4'd1) uart_tx <= 1'b0;  // 0
                        else if (tx_bit_cnt == 4'd2) uart_tx <= 1'b0;  // 0
                        else if (tx_bit_cnt == 4'd3) uart_tx <= 1'b1;  // 1
                        else if (tx_bit_cnt == 4'd4) uart_tx <= 1'b0;  // 0
                        else if (tx_bit_cnt == 4'd5) uart_tx <= 1'b1;  // 1
                        else if (tx_bit_cnt == 4'd6) uart_tx <= 1'b0;  // 0
                        else if (tx_bit_cnt == 4'd7) uart_tx <= 1'b1;  // 1
                        else if (tx_bit_cnt == 4'd8) uart_tx <= 1'b1;  // 1
                        else if (tx_bit_cnt == 4'd9) uart_tx <= 1'b0;  // 0
                        else begin
                            uart_tx <= 1'b1;  // Stop
                            tx_state <= TX_DONE;
                        end
                    end
                end

                TX_DONE: begin
                    tx_state <= TX_IDLE;
                    led <= 1'b0;
                end
            endcase
        end
    end

endmodule
