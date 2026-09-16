//---------------------------------------------------------------
// uart_rx.v
// UART Receiver cho AEGIS-AES FPGA Demo
// 8N1, 115200 baud
//---------------------------------------------------------------
`default_nettype none

module uart_rx #(
    parameter CLK_FREQ = 50_000_000,
    parameter BAUD_RATE = 115200,
    parameter BIT_PERIOD = CLK_FREQ / BAUD_RATE
) (
    input  wire       clk,
    input  wire       rst_n,
    input  wire       uart_rx,
    output reg  [7:0] rx_data,
    output reg        rx_valid,
    output reg        rx_frame_err
);

    localparam BIT_TIME_HALF = BIT_PERIOD / 2;

    reg [15:0] baud_cnt;
    reg [2:0] bit_idx;
    reg [7:0] rx_shift;
    reg [1:0] uart_rx_sync;
    reg sampling;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            uart_rx_sync <= 2'b11;
        end else begin
            uart_rx_sync <= {uart_rx_sync[0], uart_rx};
        end
    end

    wire uart_rx_clean = uart_rx_sync[1];

    localparam RX_IDLE  = 2'd0;
    localparam RX_START = 2'd1;
    localparam RX_DATA  = 2'd2;
    localparam RX_STOP  = 2'd3;

    reg [1:0] rx_state;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            rx_state     <= RX_IDLE;
            rx_valid     <= 1'b0;
            rx_frame_err <= 1'b0;
            rx_data      <= 8'd0;
            rx_shift     <= 8'd0;
            bit_idx      <= 3'd0;
            baud_cnt     <= 16'd0;
            sampling     <= 1'b0;
        end else begin
            rx_valid     <= 1'b0;
            rx_frame_err <= 1'b0;

            case (rx_state)
                RX_IDLE: begin
                    if (!uart_rx_clean) begin
                        rx_state  <= RX_START;
                        baud_cnt  <= BIT_TIME_HALF[15:0];
                        sampling  <= 1'b0;
                    end
                end

                RX_START: begin
                    if (baud_cnt == 16'd0) begin
                        if (!uart_rx_clean) begin
                            rx_state <= RX_DATA;
                            bit_idx  <= 3'd0;
                            baud_cnt <= BIT_PERIOD[15:0];
                        end else begin
                            rx_state <= RX_IDLE;
                        end
                    end else begin
                        baud_cnt <= baud_cnt - 16'd1;
                    end
                end

                RX_DATA: begin
                    if (baud_cnt == 16'd0) begin
                        rx_shift[bit_idx] <= uart_rx_clean;
                        bit_idx           <= bit_idx + 3'd1;
                        if (bit_idx == 3'd7) begin
                            rx_state <= RX_STOP;
                        end
                        baud_cnt <= BIT_PERIOD[15:0];
                    end else begin
                        baud_cnt <= baud_cnt - 16'd1;
                    end
                end

                RX_STOP: begin
                    if (baud_cnt == 16'd0) begin
                        if (uart_rx_clean) begin
                            rx_data  <= rx_shift;
                            rx_valid <= 1'b1;
                        end else begin
                            rx_frame_err <= 1'b1;
                        end
                        rx_state <= RX_IDLE;
                    end else begin
                        baud_cnt <= baud_cnt - 16'd1;
                    end
                end
            endcase
        end
    end

endmodule

`default_nettype wire
