// ============================================================================
// Project     : AEGIS-AES
// Module      : uart_frame_tx
// Description : Serialize UART response frame 37 byte.
//               Response fields use big-endian byte order.
// ============================================================================

`default_nettype none

module uart_frame_tx (
  input  wire         clk,
  input  wire         rst_n,

  input  wire         rsp_start,
  input  wire [7:0]   rsp_seq,
  input  wire [7:0]   rsp_flags,
  input  wire [7:0]   rsp_sec_status,
  input  wire [127:0] rsp_raw_out,
  input  wire [127:0] rsp_protected_out,

  output reg          rsp_busy,
  output reg          rsp_done,

  output reg  [7:0]   tx_data,
  output reg          tx_start,
  input  wire         tx_busy,
  input  wire         tx_done
);

  //----------------------------------------------------------------
  // State encoding.
  //----------------------------------------------------------------
  localparam [1:0] ST_IDLE      = 2'd0;
  localparam [1:0] ST_SEND_BYTE = 2'd1;
  localparam [1:0] ST_WAIT_DONE = 2'd2;

  //----------------------------------------------------------------
  // Latched response fields.
  //----------------------------------------------------------------
  reg [7:0] seq_reg;
  reg [7:0] flags_reg;
  reg [7:0] sec_status_reg;

  reg [127:0] raw_shift_reg;
  reg [127:0] protected_shift_reg;

  //----------------------------------------------------------------
  // Serializer registers.
  //----------------------------------------------------------------
  reg [1:0] state_reg;
  reg [5:0] byte_index_reg;
  reg [7:0] checksum_reg;

  //----------------------------------------------------------------
  // Response serializer.
  //----------------------------------------------------------------
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state_reg <= ST_IDLE;
      byte_index_reg <= 6'd0;
      checksum_reg <= 8'd0;

      seq_reg <= 8'd0;
      flags_reg <= 8'd0;
      sec_status_reg <= 8'd0;
      raw_shift_reg <= 128'd0;
      protected_shift_reg <= 128'd0;

      rsp_busy <= 1'b0;
      rsp_done <= 1'b0;

      tx_data <= 8'd0;
      tx_start <= 1'b0;
    end else begin
      // Event outputs chi duoc phep keo dai mot clock.
      rsp_done <= 1'b0;
      tx_start <= 1'b0;

      case (state_reg)
        //----------------------------------------------------------
        // Wait for a new response.
        //----------------------------------------------------------
        ST_IDLE: begin
          rsp_busy <= 1'b0;
          byte_index_reg <= 6'd0;
          checksum_reg <= 8'd0;

          if (rsp_start) begin
            seq_reg <= rsp_seq;
            flags_reg <= rsp_flags;
            sec_status_reg <= rsp_sec_status;
            raw_shift_reg <= rsp_raw_out;
            protected_shift_reg <= rsp_protected_out;

            rsp_busy <= 1'b1;
            state_reg <= ST_SEND_BYTE;
          end
        end

        //----------------------------------------------------------
        // Present one byte to uart_tx.
        //----------------------------------------------------------
        ST_SEND_BYTE: begin
          rsp_busy <= 1'b1;

          if (!tx_busy) begin
            //------------------------------------------------------
            // Byte 0: response header.
            //------------------------------------------------------
            if (byte_index_reg == 6'd0) begin
              tx_data <= 8'h5A;
              checksum_reg <= checksum_reg ^ 8'h5A;
              tx_start <= 1'b1;
              state_reg <= ST_WAIT_DONE;
            end

            //------------------------------------------------------
            // Byte 1: sequence number.
            //------------------------------------------------------
            else if (byte_index_reg == 6'd1) begin
              tx_data <= seq_reg;
              checksum_reg <= checksum_reg ^ seq_reg;
              tx_start <= 1'b1;
              state_reg <= ST_WAIT_DONE;
            end

            //------------------------------------------------------
            // Byte 2: flags.
            //------------------------------------------------------
            else if (byte_index_reg == 6'd2) begin
              tx_data <= flags_reg;
              checksum_reg <= checksum_reg ^ flags_reg;
              tx_start <= 1'b1;
              state_reg <= ST_WAIT_DONE;
            end

            //------------------------------------------------------
            // Byte 3: security status.
            //------------------------------------------------------
            else if (byte_index_reg == 6'd3) begin
              tx_data <= sec_status_reg;
              checksum_reg <= checksum_reg ^ sec_status_reg;
              tx_start <= 1'b1;
              state_reg <= ST_WAIT_DONE;
            end

            //------------------------------------------------------
            // Bytes 4-19: raw output, big-endian.
            //------------------------------------------------------
            else if ((byte_index_reg >= 6'd4) &&
                     (byte_index_reg <= 6'd19)) begin
              tx_data <= raw_shift_reg[127:120];
              checksum_reg <=
                checksum_reg ^ raw_shift_reg[127:120];

              raw_shift_reg <=
                {raw_shift_reg[119:0], 8'd0};

              tx_start <= 1'b1;
              state_reg <= ST_WAIT_DONE;
            end

            //------------------------------------------------------
            // Bytes 20-35: protected output, big-endian.
            //------------------------------------------------------
            else if ((byte_index_reg >= 6'd20) &&
                     (byte_index_reg <= 6'd35)) begin
              tx_data <= protected_shift_reg[127:120];
              checksum_reg <=
                checksum_reg ^ protected_shift_reg[127:120];

              protected_shift_reg <=
                {protected_shift_reg[119:0], 8'd0};

              tx_start <= 1'b1;
              state_reg <= ST_WAIT_DONE;
            end

            //------------------------------------------------------
            // Byte 36: XOR checksum of bytes 0-35.
            //------------------------------------------------------
            else if (byte_index_reg == 6'd36) begin
              tx_data <= checksum_reg;
              tx_start <= 1'b1;
              state_reg <= ST_WAIT_DONE;
            end

            //------------------------------------------------------
            // Fail-safe recovery from illegal byte index.
            //------------------------------------------------------
            else begin
              state_reg <= ST_IDLE;
              byte_index_reg <= 6'd0;
              checksum_reg <= 8'd0;

              rsp_busy <= 1'b0;
              tx_data <= 8'd0;
            end
          end
        end

        //----------------------------------------------------------
        // Wait until uart_tx finishes the current byte.
        //----------------------------------------------------------
        ST_WAIT_DONE: begin
          rsp_busy <= 1'b1;

          if (tx_done) begin
            if (byte_index_reg == 6'd36) begin
              byte_index_reg <= 6'd0;
              rsp_busy <= 1'b0;
              rsp_done <= 1'b1;
              state_reg <= ST_IDLE;
            end else begin
              byte_index_reg <= byte_index_reg + 1'b1;
              state_reg <= ST_SEND_BYTE;
            end
          end
        end

        //----------------------------------------------------------
        // Fail-safe recovery from illegal FSM state.
        //----------------------------------------------------------
        default: begin
          state_reg <= ST_IDLE;
          byte_index_reg <= 6'd0;
          checksum_reg <= 8'd0;

          rsp_busy <= 1'b0;
          rsp_done <= 1'b0;

          tx_data <= 8'd0;
          tx_start <= 1'b0;
        end
      endcase
    end
  end

endmodule

`default_nettype wire
