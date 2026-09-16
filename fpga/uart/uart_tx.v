//---------------------------------------------------------------
// uart_tx.v
// UART Transmitter cho AEGIS-AES FPGA Demo
// 8N1, 115200 baud
//---------------------------------------------------------------
`default_nettype none

module uart_tx #(
    parameter CLK_FREQ = 50_000_000,
    parameter BAUD_RATE = 115200,
    parameter BIT_PERIOD = CLK_FREQ / BAUD_RATE
) (
    input  wire       clk,
    input  wire       rst_n,
    input  wire [7:0] tx_data,
    input  wire       tx_valid,
    output reg        uart_tx,
    output reg        tx_ready
);

    localparam BIT_TIME_HALF = BIT_PERIOD / 2;

    reg [15:0] baud_cnt;
    reg [2:0] bit_idx;
    reg [7:0] tx_shift;
    reg sending;

    localparam TX_IDLE  = 2'd0;
    localparam TX_START = 2'd1;
    localparam TX_DATA  = 2'd2;
    localparam TX_STOP  = 2'd3;

    reg [1:0] tx_state;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            tx_state  <= TX_IDLE;
            uart_tx   <= 1'b1;
            tx_ready  <= 1'b1;
            tx_shift  <= 8'd0;
            bit_idx   <= 3'd0;
            baud_cnt  <= 16'd0;
            sending   <= 1'b0;
        end else begin
            case (tx_state)
                TX_IDLE: begin
                    uart_tx  <= 1'b1;
                    tx_ready <= 1'b1;

                    if (tx_valid && !sending) begin
                        tx_shift <= tx_data;
                        tx_ready <= 1'b0;
                        tx_state <= TX_START;
                        baud_cnt <= 16'd0;
                    end
                end

                TX_START: begin
                    uart_tx <= 1'b0;
                    tx_ready <= 1'b0;
                    sending  <= 1'b1;

                    if (baud_cnt == BIT_PERIOD - 1) begin
                        baud_cnt <= 16'd0;
                        bit_idx  <= 3'd0;
                        tx_state <= TX_DATA;
                    end else begin
                        baud_cnt <= baud_cnt + 1'b1;
                    end
                end

                TX_DATA: begin
                    uart_tx <= tx_shift[0];

                    if (baud_cnt == BIT_PERIOD - 1) begin
                        baud_cnt <= 16'd0;
                        tx_shift <= {1'b0, tx_shift[7:1]};

                        if (bit_idx == 3'd7) begin
                            tx_state <= TX_STOP;
                        end else begin
                            bit_idx <= bit_idx + 1'b1;
                        end
                    end else begin
                        baud_cnt <= baud_cnt + 1'b1;
                    end
                end

                TX_STOP: begin
                    uart_tx <= 1'b1;

                    if (baud_cnt == BIT_PERIOD - 1) begin
                        tx_state <= TX_IDLE;
                        sending  <= 1'b0;
                        baud_cnt <= 16'd0;
                    end else begin
                        baud_cnt <= baud_cnt + 1'b1;
                    end
                end

                default: tx_state <= TX_IDLE;
            endcase
        end
    end

endmodule

//======================================================================
// EOF uart_tx.v
//======================================================================
