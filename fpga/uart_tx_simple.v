//---------------------------------------------------------------
// uart_tx_simple.v
// Simple UART TX - continuously sends 'X' character
//---------------------------------------------------------------
`default_nettype none

module uart_tx_simple (
    input  wire clk,
    input  wire rst_n,
    output reg  uart_tx,
    output reg  led
);

    // State machine
    reg [3:0] state;
    localparam IDLE  = 4'd0;
    localparam START = 4'd1;
    localparam BIT0  = 4'd2;
    localparam BIT1  = 4'd3;
    localparam BIT2  = 4'd4;
    localparam BIT3  = 4'd5;
    localparam BIT4  = 4'd6;
    localparam BIT5  = 4'd7;
    localparam BIT6  = 4'd8;
    localparam BIT7  = 4'd9;
    localparam STOP  = 4'd10;

    // TX data = 'X' = 0x58
    localparam TX_DATA = 8'h58;

    // Baud counter (~115200 baud at 50MHz)
    reg [15:0] baud_cnt;
    localparam BAUD_MAX = 16'd434;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            uart_tx <= 1'b1;  // Idle high
            led <= 1'b0;
            baud_cnt <= 16'd0;
        end else begin
            case (state)
                IDLE: begin
                    uart_tx <= 1'b1;
                    led <= 1'b0;
                    baud_cnt <= 16'd0;
                    state <= START;
                end

                START: begin
                    uart_tx <= 1'b0;  // Start bit
                    led <= 1'b1;
                    if (baud_cnt >= BAUD_MAX - 1) begin
                        baud_cnt <= 16'd0;
                        state <= BIT0;
                    end else begin
                        baud_cnt <= baud_cnt + 1'b1;
                    end
                end

                BIT0: begin
                    uart_tx <= TX_DATA[0];
                    if (baud_cnt >= BAUD_MAX - 1) begin
                        baud_cnt <= 16'd0;
                        state <= BIT1;
                    end else begin
                        baud_cnt <= baud_cnt + 1'b1;
                    end
                end

                BIT1: begin
                    uart_tx <= TX_DATA[1];
                    if (baud_cnt >= BAUD_MAX - 1) begin
                        baud_cnt <= 16'd0;
                        state <= BIT2;
                    end else begin
                        baud_cnt <= baud_cnt + 1'b1;
                    end
                end

                BIT2: begin
                    uart_tx <= TX_DATA[2];
                    if (baud_cnt >= BAUD_MAX - 1) begin
                        baud_cnt <= 16'd0;
                        state <= BIT3;
                    end else begin
                        baud_cnt <= baud_cnt + 1'b1;
                    end
                end

                BIT3: begin
                    uart_tx <= TX_DATA[3];
                    if (baud_cnt >= BAUD_MAX - 1) begin
                        baud_cnt <= 16'd0;
                        state <= BIT4;
                    end else begin
                        baud_cnt <= baud_cnt + 1'b1;
                    end
                end

                BIT4: begin
                    uart_tx <= TX_DATA[4];
                    if (baud_cnt >= BAUD_MAX - 1) begin
                        baud_cnt <= 16'd0;
                        state <= BIT5;
                    end else begin
                        baud_cnt <= baud_cnt + 1'b1;
                    end
                end

                BIT5: begin
                    uart_tx <= TX_DATA[5];
                    if (baud_cnt >= BAUD_MAX - 1) begin
                        baud_cnt <= 16'd0;
                        state <= BIT6;
                    end else begin
                        baud_cnt <= baud_cnt + 1'b1;
                    end
                end

                BIT6: begin
                    uart_tx <= TX_DATA[6];
                    if (baud_cnt >= BAUD_MAX - 1) begin
                        baud_cnt <= 16'd0;
                        state <= BIT7;
                    end else begin
                        baud_cnt <= baud_cnt + 1'b1;
                    end
                end

                BIT7: begin
                    uart_tx <= TX_DATA[7];
                    if (baud_cnt >= BAUD_MAX - 1) begin
                        baud_cnt <= 16'd0;
                        state <= STOP;
                    end else begin
                        baud_cnt <= baud_cnt + 1'b1;
                    end
                end

                STOP: begin
                    uart_tx <= 1'b1;  // Stop bit
                    if (baud_cnt >= BAUD_MAX - 1) begin
                        baud_cnt <= 16'd0;
                        state <= IDLE;
                    end else begin
                        baud_cnt <= baud_cnt + 1'b1;
                    end
                end

                default: state <= IDLE;
            endcase
        end
    end

endmodule
