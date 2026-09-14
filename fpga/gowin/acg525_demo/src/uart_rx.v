// ============================================================================
// Project     : AEGIS-AES
// Module      : uart_rx
// Description : UART receiver, 8 data bits, no parity, 1 stop bit.
//               Du lieu duoc nhan theo thu tu LSB-first.
// ============================================================================

`default_nettype none

module uart_rx #(
  parameter [15:0] CLKS_PER_BIT = 16'd434
) (
  input  wire       clk,
  input  wire       rst_n,

  input  wire       rx,

  output reg  [7:0] rx_data,
  output reg        rx_valid,
  output reg        frame_error
);

  //----------------------------------------------------------------
  // Parameters and state encoding.
  //----------------------------------------------------------------
  localparam [15:0] HALF_CLKS_PER_BIT = CLKS_PER_BIT >> 1;

  localparam [1:0] ST_IDLE  = 2'd0;
  localparam [1:0] ST_START = 2'd1;
  localparam [1:0] ST_DATA  = 2'd2;
  localparam [1:0] ST_STOP  = 2'd3;

  //----------------------------------------------------------------
  // Registers.
  //----------------------------------------------------------------
  reg        rx_meta_reg;
  reg        rx_sync_reg;

  reg [1:0]  state_reg;
  reg [15:0] clk_count_reg;
  reg [2:0]  bit_index_reg;
  reg [7:0]  data_reg;

  //----------------------------------------------------------------
  // Synchronize asynchronous UART input.
  //
  // rx_meta_reg co the roi vao metastability.
  // rx_sync_reg la tin hieu da dong bo dung cho FSM.
  //----------------------------------------------------------------
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      rx_meta_reg <= 1'b1;
      rx_sync_reg <= 1'b1;
    end else begin
      rx_meta_reg <= rx;
      rx_sync_reg <= rx_meta_reg;
    end
  end

  //----------------------------------------------------------------
  // UART receiver FSM.
  //----------------------------------------------------------------
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state_reg     <= ST_IDLE;
      clk_count_reg <= 16'd0;
      bit_index_reg <= 3'd0;
      data_reg      <= 8'd0;

      rx_data       <= 8'd0;
      rx_valid      <= 1'b0;
      frame_error   <= 1'b0;
    end else begin
      // Hai tin hieu nay chi duoc phep keo dai mot chu ky.
      rx_valid    <= 1'b0;
      frame_error <= 1'b0;

      case (state_reg)
        //----------------------------------------------------------
        // Cho canh xuong cua start bit.
        //----------------------------------------------------------
        ST_IDLE: begin
          clk_count_reg <= 16'd0;
          bit_index_reg <= 3'd0;

          if (rx_sync_reg == 1'b0) begin
            state_reg <= ST_START;
          end
        end

        //----------------------------------------------------------
        // Cho toi giua start bit va kiem tra lai muc thap.
        //
        // Neu RX da tro lai muc cao thi day la start bit gia.
        //----------------------------------------------------------
        ST_START: begin
          if (clk_count_reg == HALF_CLKS_PER_BIT - 16'd1) begin
            clk_count_reg <= 16'd0;

            if (rx_sync_reg == 1'b0) begin
              bit_index_reg <= 3'd0;
              state_reg     <= ST_DATA;
            end else begin
              state_reg <= ST_IDLE;
            end
          end else begin
            clk_count_reg <= clk_count_reg + 1'b1;
          end
        end

        //----------------------------------------------------------
        // Lay mau 8 data bit, moi bit cach nhau CLKS_PER_BIT.
        //----------------------------------------------------------
        ST_DATA: begin
          if (clk_count_reg == CLKS_PER_BIT - 16'd1) begin
            clk_count_reg             <= 16'd0;
            data_reg[bit_index_reg]    <= rx_sync_reg;

            if (bit_index_reg == 3'd7) begin
              state_reg <= ST_STOP;
            end else begin
              bit_index_reg <= bit_index_reg + 1'b1;
            end
          end else begin
            clk_count_reg <= clk_count_reg + 1'b1;
          end
        end

        //----------------------------------------------------------
        // Lay mau stop bit sau mot chu ky bit.
        //
        // Stop bit dung:
        //   - cap nhat rx_data;
        //   - phat rx_valid mot clock.
        //
        // Stop bit sai:
        //   - phat frame_error mot clock;
        //   - khong phat rx_valid.
        //----------------------------------------------------------
        ST_STOP: begin
          if (clk_count_reg == CLKS_PER_BIT - 16'd1) begin
            clk_count_reg <= 16'd0;
            state_reg     <= ST_IDLE;

            if (rx_sync_reg == 1'b1) begin
              rx_data  <= data_reg;
              rx_valid <= 1'b1;
            end else begin
              frame_error <= 1'b1;
            end
          end else begin
            clk_count_reg <= clk_count_reg + 1'b1;
          end
        end

        //----------------------------------------------------------
        // Fail-safe: dua bo nhan ve trang thai cho.
        //----------------------------------------------------------
        default: begin
          state_reg     <= ST_IDLE;
          clk_count_reg <= 16'd0;
          bit_index_reg <= 3'd0;
          data_reg      <= 8'd0;

          rx_valid      <= 1'b0;
          frame_error   <= 1'b0;
        end
      endcase
    end
  end

endmodule

`default_nettype wire
