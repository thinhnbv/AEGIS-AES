//---------------------------------------------------------------
// uart_tx_test.v
// UART TX test - sends 'X' when button pressed
//---------------------------------------------------------------
`default_nettype none

module uart_tx_test (
    input  wire clk,
    input  wire rst_n,
    input  wire uart_rx,
    output reg  uart_tx,
    output reg  led_rx,
    output reg  led_tx
);

    // States
    reg [3:0] state;
    localparam IDLE = 4'd0;
    localparam SEND = 4'd1;

    // TX signals
    reg [7:0] tx_data;
    reg tx_start;
    reg [3:0] tx_bit_cnt;
    reg [15:0] tx_baud_cnt;
    localparam BIT_PERIOD = 16'd434;  // 50MHz / 115200

    // RX LED pulse
    reg [23:0] rx_pulse_cnt;
    localparam RX_PULSE = 24'd1_000_000;  // ~20ms

    // TX LED pulse
    reg [23:0] tx_pulse_cnt;
    localparam TX_PULSE = 24'd500_000;  // ~10ms

    // Edge detection for RX
    reg uart_rx_prev;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            uart_tx <= 1'b1;
            tx_data <= 8'h00;
            tx_start <= 1'b0;
            tx_bit_cnt <= 4'd0;
            tx_baud_cnt <= 16'd0;
            led_rx <= 1'b0;
            led_tx <= 1'b0;
            uart_rx_prev <= 1'b1;
            rx_pulse_cnt <= 24'd0;
            tx_pulse_cnt <= 24'd0;
        end else begin
            // Edge detection for RX
            uart_rx_prev <= uart_rx;

            // RX LED pulse
            if (uart_rx_prev == 1'b1 && uart_rx == 1'b0) begin
                led_rx <= 1'b1;
                rx_pulse_cnt <= RX_PULSE;
            end else if (rx_pulse_cnt > 24'd0) begin
                rx_pulse_cnt <= rx_pulse_cnt - 1'b1;
            end else begin
                led_rx <= 1'b0;
            end

            // TX LED pulse
            if (tx_pulse_cnt > 24'd0) begin
                tx_pulse_cnt <= tx_pulse_cnt - 1'b1;
                led_tx <= 1'b1;
            end else begin
                led_tx <= 1'b0;
            end

            // TX state machine
            case (state)
                IDLE: begin
                    tx_start <= 1'b0;
                    tx_bit_cnt <= 4'd0;
                    tx_baud_cnt <= 16'd0;

                    // Trigger on falling edge (start bit)
                    if (uart_rx_prev == 1'b1 && uart_rx == 1'b0) begin
                        tx_data <= 8'h58;  // 'X'
                        tx_start <= 1'b1;
                        state <= SEND;
                    end
                end

                SEND: begin
                    if (tx_start) begin
                        tx_baud_cnt <= tx_baud_cnt + 1'b1;

                        if (tx_baud_cnt >= BIT_PERIOD - 1) begin
                            tx_baud_cnt <= 16'd0;
                            tx_bit_cnt <= tx_bit_cnt + 1'b1;

                            // Send bits
                            if (tx_bit_cnt == 4'd0) begin
                                uart_tx <= 1'b0;  // Start bit
                            end else if (tx_bit_cnt >= 4'd1 && tx_bit_cnt <= 4'd8) begin
                                uart_tx <= tx_data[tx_bit_cnt - 1];  // Data bits
                            end else if (tx_bit_cnt == 4'd9) begin
                                uart_tx <= 1'b1;  // Stop bit
                            end else begin
                                state <= IDLE;
                                tx_pulse_cnt <= TX_PULSE;
                            end
                        end
                    end
                end
            endcase
        end
    end

endmodule
