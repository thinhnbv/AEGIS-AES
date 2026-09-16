//======================================================================
// uart_tx_core.v
// UART Transmitter - Gowin standard module
// 115200 baud, 8N1
//======================================================================
`default_nettype none

module uart_tx_core (
    input wire clk,
    input wire rst_n,
    input wire [7:0] tx_data,
    input wire tx_start,
    output wire tx_serial,
    output wire tx_busy
);

    localparam IDLE = 3'd0;
    localparam START = 3'd1;
    localparam DATA = 3'd2;
    localparam STOP = 3'd3;

    parameter BAUD_DIV = 434;

    reg [2:0] state, next_state;
    reg [12:0] baud_counter;
    reg [2:0] bit_index;
    reg [7:0] tx_shift;
    reg tx_reg;

    wire bit_timer_done = (baud_counter == BAUD_DIV - 1);

    always @(posedge clk) begin
        if (!rst_n)
            baud_counter <= 0;
        else if (state == IDLE)
            baud_counter <= 0;
        else if (bit_timer_done)
            baud_counter <= 0;
        else
            baud_counter <= baud_counter + 1;
    end

    always @(posedge clk) begin
        if (!rst_n) begin
            bit_index <= 0;
            tx_shift <= 0;
        end else if (state == IDLE && tx_start) begin
            tx_shift <= tx_data;
            bit_index <= 0;
        end else if (state == DATA && bit_timer_done) begin
            tx_shift <= tx_shift >> 1;
            bit_index <= bit_index + 1;
        end
    end

    always @(posedge clk) begin
        if (!rst_n)
            tx_reg <= 1'b1;
        else begin
            case (state)
                IDLE:  tx_reg <= 1'b1;
                START: tx_reg <= 1'b0;
                DATA:  tx_reg <= tx_shift[0];
                STOP:  tx_reg <= 1'b1;
                default: tx_reg <= 1'b1;
            endcase
        end
    end

    always @(posedge clk) begin
        if (!rst_n)
            state <= IDLE;
        else
            state <= next_state;
    end

    always @(*) begin
        case (state)
            IDLE:   next_state = tx_start ? START : IDLE;
            START:  next_state = bit_timer_done ? DATA : START;
            DATA:   next_state = (bit_timer_done && bit_index == 7) ? STOP : DATA;
            STOP:   next_state = bit_timer_done ? IDLE : STOP;
            default: next_state = IDLE;
        endcase
    end

    assign tx_busy = (state != IDLE);
    assign tx_serial = tx_reg;

endmodule
