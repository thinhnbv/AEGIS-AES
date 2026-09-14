// ============================================================================
// Project     : AEGIS-AES
// Module      : uart_frame_rx
// Description : Parse UART request frame 36 byte.
//               Request fields use big-endian byte order.
// ============================================================================

`default_nettype none

module uart_frame_rx #(
  parameter [31:0] INTERBYTE_TIMEOUT_CLKS = 32'd500000
) (
  input  wire         clk,
  input  wire         rst_n,

  input  wire [7:0]   rx_data,
  input  wire         rx_valid,
  input  wire         rx_frame_error,

  output wire         frame_busy,

  output reg          req_valid,
  output reg          req_error_valid,

  output reg  [7:0]   req_seq,
  output reg  [127:0] req_key,
  output reg  [127:0] req_plaintext
);

  //----------------------------------------------------------------
  // Registers.
  //----------------------------------------------------------------
  reg        frame_active_reg;
  reg        command_valid_reg;

  // Vi tri byte tiep theo trong frame.
  // 0  : header
  // 1  : command
  // 2  : sequence
  // 3-18  : key
  // 19-34 : plaintext
  // 35 : checksum
  reg [5:0] byte_index_reg;

  reg [7:0]  checksum_reg;
  reg [31:0] timeout_count_reg;

  //----------------------------------------------------------------
  // Output mapping.
  //----------------------------------------------------------------
  assign frame_busy = frame_active_reg;

  //----------------------------------------------------------------
  // Request parser.
  //----------------------------------------------------------------
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      frame_active_reg <= 1'b0;
      command_valid_reg <= 1'b0;
      byte_index_reg <= 6'd0;
      checksum_reg <= 8'd0;
      timeout_count_reg <= 32'd0;

      req_valid <= 1'b0;
      req_error_valid <= 1'b0;
      req_seq <= 8'd0;
      req_key <= 128'd0;
      req_plaintext <= 128'd0;
    end else begin
      // Event outputs chi duoc phep keo dai mot clock.
      req_valid <= 1'b0;
      req_error_valid <= 1'b0;

      //------------------------------------------------------------
      // Physical UART error has highest priority.
      //------------------------------------------------------------
      if (rx_frame_error) begin
        req_error_valid <= 1'b1;

        if (!frame_active_reg)
          req_seq <= 8'd0;

        frame_active_reg <= 1'b0;
        command_valid_reg <= 1'b0;
        byte_index_reg <= 6'd0;
        checksum_reg <= 8'd0;
        timeout_count_reg <= 32'd0;

        req_key <= 128'd0;
        req_plaintext <= 128'd0;
      end

      //------------------------------------------------------------
      // Consume one received byte.
      //------------------------------------------------------------
      else if (rx_valid) begin
        timeout_count_reg <= 32'd0;

        //----------------------------------------------------------
        // Idle: ignore all bytes until header A5.
        //----------------------------------------------------------
        if (!frame_active_reg) begin
          if (rx_data == 8'hA5) begin
            frame_active_reg <= 1'b1;
            command_valid_reg <= 1'b0;
            byte_index_reg <= 6'd1;
            checksum_reg <= 8'hA5;

            req_seq <= 8'd0;
            req_key <= 128'd0;
            req_plaintext <= 128'd0;
          end
        end

        //----------------------------------------------------------
        // Byte 1: command.
        //----------------------------------------------------------
        else if (byte_index_reg == 6'd1) begin
          command_valid_reg <= (rx_data == 8'h01);
          checksum_reg <= checksum_reg ^ rx_data;
          byte_index_reg <= 6'd2;
        end

        //----------------------------------------------------------
        // Byte 2: sequence number.
        //----------------------------------------------------------
        else if (byte_index_reg == 6'd2) begin
          req_seq <= rx_data;
          checksum_reg <= checksum_reg ^ rx_data;
          byte_index_reg <= 6'd3;
        end

        //----------------------------------------------------------
        // Bytes 3-18: 128-bit key, big-endian.
        //----------------------------------------------------------
        else if ((byte_index_reg >= 6'd3) &&
                 (byte_index_reg <= 6'd18)) begin
          req_key <= {req_key[119:0], rx_data};
          checksum_reg <= checksum_reg ^ rx_data;
          byte_index_reg <= byte_index_reg + 1'b1;
        end

        //----------------------------------------------------------
        // Bytes 19-34: 128-bit plaintext, big-endian.
        //----------------------------------------------------------
        else if ((byte_index_reg >= 6'd19) &&
                 (byte_index_reg <= 6'd34)) begin
          req_plaintext <= {req_plaintext[119:0], rx_data};
          checksum_reg <= checksum_reg ^ rx_data;
          byte_index_reg <= byte_index_reg + 1'b1;
        end

        //----------------------------------------------------------
        // Byte 35: received checksum.
        //----------------------------------------------------------
        else if (byte_index_reg == 6'd35) begin
          frame_active_reg <= 1'b0;
          byte_index_reg <= 6'd0;
          timeout_count_reg <= 32'd0;

          if (command_valid_reg &&
              (rx_data == checksum_reg)) begin
            req_valid <= 1'b1;
          end else begin
            req_error_valid <= 1'b1;
            req_key <= 128'd0;
            req_plaintext <= 128'd0;
          end
        end

        //----------------------------------------------------------
        // Fail-secure recovery from illegal byte index.
        //----------------------------------------------------------
        else begin
          frame_active_reg <= 1'b0;
          command_valid_reg <= 1'b0;
          byte_index_reg <= 6'd0;
          checksum_reg <= 8'd0;
          timeout_count_reg <= 32'd0;

          req_error_valid <= 1'b1;
          req_key <= 128'd0;
          req_plaintext <= 128'd0;
        end
      end

      //------------------------------------------------------------
      // Inter-byte timeout while a frame is active.
      //------------------------------------------------------------
      else if (frame_active_reg) begin
        if (timeout_count_reg ==
            INTERBYTE_TIMEOUT_CLKS - 32'd1) begin
          frame_active_reg <= 1'b0;
          command_valid_reg <= 1'b0;
          byte_index_reg <= 6'd0;
          checksum_reg <= 8'd0;
          timeout_count_reg <= 32'd0;

          req_error_valid <= 1'b1;
          req_key <= 128'd0;
          req_plaintext <= 128'd0;
        end else begin
          timeout_count_reg <= timeout_count_reg + 1'b1;
        end
      end

      //------------------------------------------------------------
      // Idle housekeeping.
      //------------------------------------------------------------
      else begin
        timeout_count_reg <= 32'd0;
      end
    end
  end

endmodule

`default_nettype wire
