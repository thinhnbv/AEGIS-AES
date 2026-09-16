//---------------------------------------------------------------
// uart_tx_test.v
// UART TX test - sends 'X' continuously when button pressed
//---------------------------------------------------------------
`default_nettype none

module uart_tx_test (
    input  wire clk,
    input  wire rst_n,
    input  wire uart_rx,
    output wire uart_tx,
    output reg  led_rx,
    output reg  led_tx
);

    // UART signals
    reg [7:0] tx_data;
    reg tx_valid;
    wire tx_ready;

    // TX state machine
    reg [3:0] state;
    localparam IDLE = 4'd0;
    localparam SEND = 4'd1;

    // Button for triggering TX
    reg uart_rx_prev;
    reg trigger;

    // Counter for timing
    reg [23:0] counter;
    localparam BIT_PERIOD = 24'd434;  // 50MHz / 115200

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            tx_data <= 8'h00;
            tx_valid <= 1'b0;
            led_rx <= 1'b0;
            led_tx <= 1'b0;
            uart_rx_prev <= 1'b1;
            trigger <= 1'b0;
            counter <= 24'd0;
        end else begin
            // LED RX: flash on receive
            if (uart_rx_prev == 1'b1 && uart_rx == 1'b0) begin
                led_rx <= 1'b1;
                counter <= 24'd1_000_000;  // LED pulse ~20ms
            end
            if (counter > 24'd0) begin
                counter <= counter - 1'b1;
            end else begin
                led_rx <= 1'b0;
            end

            uart_rx_prev <= uart_rx;

            // TX logic: when received 'A', send back 'X'
            if (uart_rx_prev == 1'b1 && uart_rx == 1'b0) begin
                trigger <= 1'b1;
            end

            case (state)
                IDLE: begin
                    tx_valid <= 1'b0;
                    if (trigger) begin
                        tx_data <= 8'h58;  // 'X'
                        tx_valid <= 1'b1;
                        state <= SEND;
                        trigger <= 1'b0;
                    end
                end

                SEND: begin
                    if (tx_valid && tx_ready) begin
                        tx_valid <= 1'b0;
                        led_tx <= 1'b1;
                        counter <= 24'd500_000;  // LED pulse ~10ms
                    end
                    if (counter > 24'd0) begin
                        counter <= counter - 1'b1;
                    end else begin
                        led_tx <= 1'b0;
                    end
                    if (!tx_valid) begin
                        state <= IDLE;
                    end
                end
            endcase
        end
    end

    // Simple UART transmitter
    reg [3:0] tx_bit_cnt;
    reg [15:0] tx_baud_cnt;
    reg tx_bit;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            uart_tx <= 1'b1;  // Idle high
            tx_bit <= 1'b1;
            tx_bit_cnt <= 4'd0;
            tx_baud_cnt <= 16'd0;
        end else begin
            if (tx_valid && !tx_ready) begin
                // Start transmission
                case (tx_bit_cnt)
                    4'd0: begin  // Start bit
                        tx_bit <= 1'b0;
                        if (tx_baud_cnt >= BIT_PERIOD - 1) begin
                            tx_baud_cnt <= 16'd0;
                            tx_bit_cnt <= tx_bit_cnt + 1'b1;
                        end else begin
                            tx_baud_cnt <= tx_baud_cnt + 1'b1;
                        end
                    end
                    4'd1, 4'd2, 4'd3, 4'd4, 4'd5, 4'd6, 4'd7: begin  // Data bits
                        tx_bit <= tx_data[tx_bit_cnt - 1];
                        if (tx_baud_cnt >= BIT_PERIOD - 1) begin
                            tx_baud_cnt <= 16'd0;
                            tx_bit_cnt <= tx_bit_cnt + 1'b1;
                        end else begin
                            tx_baud_cnt <= tx_baud_cnt + 1'b1;
                        end
                    end
                    4'd8: begin  // Stop bit
                        tx_bit <= 1'b1;
                        if (tx_baud_cnt >= BIT_PERIOD - 1) begin
                            tx_baud_cnt <= 16'd0;
                            tx_bit_cnt <= 4'd0;
                        end else begin
                            tx_baud_cnt <= tx_baud_cnt + 1'b1;
                        end
                    end
                    default: begin
                        tx_bit_cnt <= 4'd0;
                        tx_baud_cnt <= 16'd0;
                    end
                endcase
            end
            uart_tx <= tx_bit;
        end
    end

    assign tx_ready = (tx_bit_cnt == 4'd0);

endmodule
