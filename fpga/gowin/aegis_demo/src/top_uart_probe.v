//---------------------------------------------------------------
// top_uart_probe.v
// Diagnostic-only top level: echoes bytes using aegis_demo's own
// uart_rx.v / uart_tx.v, bypassing uart_cmd_fsm and the AES core
// entirely, to isolate whether those two UART modules work on
// real hardware independently of the rest of the design.
//---------------------------------------------------------------
`default_nettype none

module top_uart_probe (
    input  wire       clk,
    input  wire       rst_n,

    input  wire       uart_rx,
    output wire       uart_tx,

    output wire [3:0] led
);

    wire [7:0] rx_data;
    wire       rx_valid;
    wire       rx_frame_err;

    reg  [7:0] tx_data_reg;
    reg        tx_valid_reg;
    wire       tx_ready;

    uart_rx u_rx (
        .clk          (clk),
        .rst_n        (rst_n),
        .uart_rx      (uart_rx),
        .rx_data      (rx_data),
        .rx_valid     (rx_valid),
        .rx_frame_err (rx_frame_err)
    );

    uart_tx u_tx (
        .clk      (clk),
        .rst_n    (rst_n),
        .tx_data  (tx_data_reg),
        .tx_valid (tx_valid_reg),
        .uart_tx  (uart_tx),
        .tx_ready (tx_ready)
    );

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            tx_valid_reg <= 1'b0;
            tx_data_reg  <= 8'd0;
        end else begin
            tx_valid_reg <= 1'b0;

            if (rx_valid && tx_ready) begin
                tx_data_reg  <= rx_data;
                tx_valid_reg <= 1'b1;
            end
        end
    end

    assign led[0] = ~uart_rx;     // raw RX line activity
    assign led[1] = rx_valid;     // pulses when uart_rx.v decodes a byte
    assign led[2] = tx_ready;     // high when uart_tx.v is idle/ready
    assign led[3] = rx_frame_err; // pulses on a bad stop bit

endmodule

//======================================================================
// EOF top_uart_probe.v
//======================================================================
