// ============================================================================
// Project     : AEGIS-AES
// Module      : uart_tx
// Description : UART transmitter, 8 data bits, no parity, 1 stop bit.
//               Du lieu duoc phat theo thu tu LSB-first.
// ============================================================================

`default_nettype none

module uart_tx #(
  parameter [15:0] CLKS_PER_BIT = 16'd434
) (
  input  wire       clk,
  input  wire       rst_n,

  input  wire       tx_start,
  input  wire [7:0] tx_data,

  output reg        tx,
  output reg        tx_busy,
  output reg        tx_done
);

  //----------------------------------------------------------------
  // State encoding.
  //----------------------------------------------------------------
  localparam [1:0] ST_IDLE  = 2'd0;
  localparam [1:0] ST_START = 2'd1;
  localparam [1:0] ST_DATA  = 2'd2;
  localparam [1:0] ST_STOP  = 2'd3;

  //----------------------------------------------------------------
  // Registers.
  //----------------------------------------------------------------
  reg [1:0]  state_reg;
  reg [15:0] clk_count_reg;
  reg [2:0]  bit_index_reg;
  reg [7:0]  data_reg;

  //----------------------------------------------------------------
  // UART transmitter.
  //----------------------------------------------------------------
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state_reg     <= ST_IDLE;
      clk_count_reg <= 16'd0;
      bit_index_reg <= 3'd0;
      data_reg      <= 8'd0;

      tx            <= 1'b1;
      tx_busy       <= 1'b0;
      tx_done       <= 1'b0;
    end else begin
      // tx_done chi duoc phep keo dai mot chu ky.
      tx_done <= 1'b0;

      case (state_reg)
        //----------------------------------------------------------
        // Cho mot yeu cau truyen moi.
        //----------------------------------------------------------
        ST_IDLE: begin
          tx            <= 1'b1;
          tx_busy       <= 1'b0;
          clk_count_reg <= 16'd0;
          bit_index_reg <= 3'd0;

          if (tx_start) begin
            data_reg      <= tx_data;
            tx             <= 1'b0;
            tx_busy        <= 1'b1;
            state_reg      <= ST_START;
          end
        end

        //----------------------------------------------------------
        // Phat start bit muc thap.
        //----------------------------------------------------------
        ST_START: begin
          tx      <= 1'b0;
          tx_busy <= 1'b1;

          if (clk_count_reg == CLKS_PER_BIT - 16'd1) begin
            clk_count_reg <= 16'd0;
            bit_index_reg <= 3'd0;

            // Bat dau phat data bit 0.
            tx        <= data_reg[0];
            state_reg <= ST_DATA;
          end else begin
            clk_count_reg <= clk_count_reg + 1'b1;
          end
        end

        //----------------------------------------------------------
        // Phat 8 data bit theo thu tu LSB-first.
        //----------------------------------------------------------
        ST_DATA: begin
          tx_busy <= 1'b1;

          if (clk_count_reg == CLKS_PER_BIT - 16'd1) begin
            clk_count_reg <= 16'd0;

            if (bit_index_reg == 3'd7) begin
              // Sau data bit 7, chuyen sang stop bit.
              tx        <= 1'b1;
              state_reg <= ST_STOP;
            end else begin
              bit_index_reg <= bit_index_reg + 1'b1;

              // Dich byte de data_reg[0] luon la bit tiep theo.
              data_reg <= {1'b0, data_reg[7:1]};
              tx       <= data_reg[1];
            end
          end else begin
            // Tiep tuc giu data bit hien tai.
            clk_count_reg <= clk_count_reg + 1'b1;
          end
        end

        //----------------------------------------------------------
        // Phat mot stop bit muc cao.
        //----------------------------------------------------------
        ST_STOP: begin
          tx      <= 1'b1;
          tx_busy <= 1'b1;

          if (clk_count_reg == CLKS_PER_BIT - 16'd1) begin
            clk_count_reg <= 16'd0;
            tx_busy       <= 1'b0;
            tx_done       <= 1'b1;
            state_reg     <= ST_IDLE;
          end else begin
            clk_count_reg <= clk_count_reg + 1'b1;
          end
        end

        //----------------------------------------------------------
        // Fail-safe: dua UART ve trang thai idle.
        //----------------------------------------------------------
        default: begin
          state_reg     <= ST_IDLE;
          clk_count_reg <= 16'd0;
          bit_index_reg <= 3'd0;
          data_reg      <= 8'd0;

          tx            <= 1'b1;
          tx_busy       <= 1'b0;
          tx_done       <= 1'b0;
        end
      endcase
    end
  end

endmodule

`default_nettype wire
