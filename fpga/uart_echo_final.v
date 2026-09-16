//---------------------------------------------------------------
// uart_echo.v
// UART Echo - receives and echoes back
//---------------------------------------------------------------
`default_nettype none

module uart_echo (
    input  wire clk,
    input  wire rst_n,
    input  wire uart_rx,
    output wire uart_tx,
    output wire led
);

    wire [7:0] rx_data;
    wire rx_valid;

    wire [7:0] tx_data;
    wire tx_valid;
    wire tx_ready;

    // UART receiver
    uart_rx uart_rx_inst (
        .clk(clk),
        .rst_n(rst_n),
        .uart_rx(uart_rx),
        .rx_data(rx_data),
        .rx_valid(rx_valid),
        .rx_frame_err()
    );

    // UART transmitter
    uart_tx uart_tx_inst (
        .clk(clk),
        .rst_n(rst_n),
        .tx_data(tx_data),
        .tx_valid(tx_valid),
        .uart_tx(uart_tx),
        .tx_ready(tx_ready)
    );

    // Echo logic
    reg [7:0] tx_data_reg;
    reg tx_valid_reg;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            tx_data_reg <= 8'h00;
            tx_valid_reg <= 1'b0;
        end else begin
            if (rx_valid && tx_ready) begin
                tx_data_reg <= rx_data;
                tx_valid_reg <= 1'b1;
            end else begin
                tx_valid_reg <= 1'b0;
            end
        end
    end

    assign tx_data = tx_data_reg;
    assign tx_valid = tx_valid_reg;

    // LED: flash on receive
    reg [23:0] led_cnt;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            led_cnt <= 24'd0;
        end else begin
            if (rx_valid) begin
                led_cnt <= 24'd1_000_000;  // ~20ms pulse
            end else if (led_cnt > 24'd0) begin
                led_cnt <= led_cnt - 1'b1;
            end
        end
    end
    assign led = (led_cnt > 24'd0);

endmodule
