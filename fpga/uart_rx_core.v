//======================================================================
// uart_rx_core.v
// UART Receiver - Gowin standard module
// 115200 baud, 8N1
//======================================================================
`default_nettype none

module uart_rx_core (
    input  wire       clk,
    input  wire       rst_n,
    input  wire       rx_serial,
    output reg  [7:0] rx_data,
    output reg        rx_valid,
    output reg        rx_error
);

    // Baud rate: 50MHz / 115200 = 434 clocks per bit
    parameter CLKS_PER_BIT = 434;
    parameter HALF_BIT = CLKS_PER_BIT / 2;

    localparam S_IDLE  = 2'd0;
    localparam S_START = 2'd1;
    localparam S_DATA  = 2'd2;
    localparam S_STOP  = 2'd3;

    reg [1:0]  state;
    reg [12:0] baud_cnt;
    reg [2:0]  bit_idx;
    reg [7:0]  rx_shift;
    reg        rx_prev;

    wire rx_falling = rx_prev & ~rx_serial;

    always @(posedge clk) begin
        if (!rst_n)
            rx_prev <= 1'b1;
        else
            rx_prev <= rx_serial;
    end

    always @(posedge clk) begin
        if (!rst_n) begin
            state    <= S_IDLE;
            baud_cnt <= 0;
            bit_idx  <= 0;
            rx_shift <= 8'd0;
            rx_data  <= 8'd0;
            rx_valid <= 1'b0;
            rx_error <= 1'b0;
        end else begin
            rx_valid <= 1'b0;
            rx_error <= 1'b0;

            case (state)
                S_IDLE: begin
                    if (rx_falling) begin
                        baud_cnt <= 0;
                        state <= S_START;
                    end
                end

                S_START: begin
                    if (baud_cnt == HALF_BIT - 1) begin
                        if (rx_serial == 1'b0) begin
                            baud_cnt <= 0;
                            bit_idx  <= 0;
                            state <= S_DATA;
                        end else begin
                            state <= S_IDLE;
                        end
                    end else begin
                        baud_cnt <= baud_cnt + 1;
                    end
                end

                S_DATA: begin
                    if (baud_cnt == CLKS_PER_BIT - 1) begin
                        baud_cnt <= 0;
                        rx_shift <= {rx_serial, rx_shift[7:1]};
                        if (bit_idx == 3'd7) begin
                            state <= S_STOP;
                        end else begin
                            bit_idx <= bit_idx + 1;
                        end
                    end else begin
                        baud_cnt <= baud_cnt + 1;
                    end
                end

                S_STOP: begin
                    if (baud_cnt == CLKS_PER_BIT - 1) begin
                        if (rx_serial == 1'b1) begin
                            rx_data  <= rx_shift;
                            rx_valid <= 1'b1;
                        end else begin
                            rx_error <= 1'b1;
                        end
                        state <= S_IDLE;
                    end else begin
                        baud_cnt <= baud_cnt + 1;
                    end
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule
