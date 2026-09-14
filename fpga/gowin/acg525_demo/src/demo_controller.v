// ============================================================================
// Project     : AEGIS-AES
// Module      : demo_controller
// Description : Coordinate raw and protected AES paths and build UART
//               response fields.
// ============================================================================

`default_nettype none

module demo_controller (
  input  wire         clk,
  input  wire         rst_n,

  input  wire         req_valid,
  input  wire         req_error_valid,
  input  wire [7:0]   req_seq,
  input  wire [127:0] req_key,
  input  wire [127:0] req_plaintext,

  output reg  [127:0] core_key,
  output reg  [127:0] core_data_in,

  output reg          raw_key_valid,
  output reg          raw_data_in_valid,
  input  wire         raw_busy,
  input  wire [127:0] raw_data_out,
  input  wire         raw_data_out_valid,

  output reg          protected_key_valid,
  output reg          protected_data_in_valid,
  input  wire         protected_busy,
  input  wire [127:0] protected_data_out,
  input  wire         protected_data_out_valid,
  input  wire         protected_sec_alarm,
  input  wire [7:0]   protected_sec_status,

  input  wire         rsp_busy,
  output reg          rsp_start,
  output reg  [7:0]   rsp_seq,
  output reg  [7:0]   rsp_flags,
  output reg  [7:0]   rsp_sec_status,
  output reg  [127:0] rsp_raw_out,
  output reg  [127:0] rsp_protected_out,

  output wire         controller_busy
);

  //----------------------------------------------------------------
  // State encoding.
  //----------------------------------------------------------------
  localparam [3:0] ST_IDLE           = 4'd0;
  localparam [3:0] ST_ISSUE_KEY      = 4'd1;
  localparam [3:0] ST_WAIT_KEY_BUSY  = 4'd2;
  localparam [3:0] ST_WAIT_KEY_DONE  = 4'd3;
  localparam [3:0] ST_ISSUE_DATA     = 4'd4;
  localparam [3:0] ST_WAIT_RESULT    = 4'd5;
  localparam [3:0] ST_SEND_RESPONSE  = 4'd6;
  localparam [3:0] ST_WAIT_RSP_BUSY  = 4'd7;
  localparam [3:0] ST_WAIT_RSP_DONE  = 4'd8;

  //----------------------------------------------------------------
  // Internal registers.
  //----------------------------------------------------------------
  reg [3:0] state_reg;

  reg [7:0] request_seq_reg;

  reg protected_enabled_reg;

  reg         raw_result_seen_reg;
  reg [127:0] raw_result_reg;

  reg         protected_result_seen_reg;
  reg [127:0] protected_result_reg;

  //----------------------------------------------------------------
  // Busy status.
  //----------------------------------------------------------------
  assign controller_busy = (state_reg != ST_IDLE);

  //----------------------------------------------------------------
  // Controller FSM.
  //----------------------------------------------------------------
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state_reg <= ST_IDLE;

      request_seq_reg <= 8'd0;
      protected_enabled_reg <= 1'b0;

      raw_result_seen_reg <= 1'b0;
      raw_result_reg <= 128'd0;

      protected_result_seen_reg <= 1'b0;
      protected_result_reg <= 128'd0;

      core_key <= 128'd0;
      core_data_in <= 128'd0;

      raw_key_valid <= 1'b0;
      raw_data_in_valid <= 1'b0;
      protected_key_valid <= 1'b0;
      protected_data_in_valid <= 1'b0;

      rsp_start <= 1'b0;
      rsp_seq <= 8'd0;
      rsp_flags <= 8'd0;
      rsp_sec_status <= 8'd0;
      rsp_raw_out <= 128'd0;
      rsp_protected_out <= 128'd0;
    end else begin
      // Control signals are one-clock pulses.
      raw_key_valid <= 1'b0;
      raw_data_in_valid <= 1'b0;
      protected_key_valid <= 1'b0;
      protected_data_in_valid <= 1'b0;
      rsp_start <= 1'b0;

      case (state_reg)
        //----------------------------------------------------------
        // Accept one request while idle.
        //----------------------------------------------------------
        ST_IDLE: begin
          //--------------------------------------------------------
          // Protocol errors have priority and never activate AES.
          //--------------------------------------------------------
          if (req_error_valid) begin
            request_seq_reg <= req_seq;

            rsp_seq <= req_seq;
            rsp_flags <=
              8'h80 |
              (protected_sec_alarm ? 8'h0C : 8'h00);

            rsp_sec_status <= protected_sec_status;
            rsp_raw_out <= 128'd0;
            rsp_protected_out <= 128'd0;

            state_reg <= ST_SEND_RESPONSE;
          end

          //--------------------------------------------------------
          // Valid AES request.
          //--------------------------------------------------------
          else if (req_valid) begin
            request_seq_reg <= req_seq;

            core_key <= req_key;
            core_data_in <= req_plaintext;

            // Once alarm is sticky, protected path is not driven.
            protected_enabled_reg <= !protected_sec_alarm;

            raw_result_seen_reg <= 1'b0;
            raw_result_reg <= 128'd0;

            protected_result_seen_reg <= 1'b0;
            protected_result_reg <= 128'd0;

            state_reg <= ST_ISSUE_KEY;
          end
        end

        //----------------------------------------------------------
        // Send key-valid pulses.
        //----------------------------------------------------------
        ST_ISSUE_KEY: begin
          raw_key_valid <= 1'b1;

          if (protected_enabled_reg &&
              !protected_sec_alarm)
            protected_key_valid <= 1'b1;

          state_reg <= ST_WAIT_KEY_BUSY;
        end

        //----------------------------------------------------------
        // Wait for the selected cores to accept the key.
        //----------------------------------------------------------
        ST_WAIT_KEY_BUSY: begin
          if (raw_busy &&
              ((!protected_enabled_reg) ||
               protected_sec_alarm ||
               protected_busy)) begin
            state_reg <= ST_WAIT_KEY_DONE;
          end
        end

        //----------------------------------------------------------
        // Wait for key expansion to finish.
        //
        // If alarm appears, protected_busy may remain high forever
        // and must no longer block controller progress.
        //----------------------------------------------------------
        ST_WAIT_KEY_DONE: begin
          if ((!raw_busy) &&
              ((!protected_enabled_reg) ||
               protected_sec_alarm ||
               (!protected_busy))) begin
            state_reg <= ST_ISSUE_DATA;
          end
        end

        //----------------------------------------------------------
        // Send data-valid pulses.
        //----------------------------------------------------------
        ST_ISSUE_DATA: begin
          raw_data_in_valid <= 1'b1;

          if (protected_enabled_reg &&
              !protected_sec_alarm)
            protected_data_in_valid <= 1'b1;

          state_reg <= ST_WAIT_RESULT;
        end

        //----------------------------------------------------------
        // Capture the two results independently.
        //----------------------------------------------------------
        ST_WAIT_RESULT: begin
          if (raw_data_out_valid) begin
            raw_result_seen_reg <= 1'b1;
            raw_result_reg <= raw_data_out;
          end

          if (protected_data_out_valid &&
              !protected_sec_alarm) begin
            protected_result_seen_reg <= 1'b1;
            protected_result_reg <= protected_data_out;
          end

          //--------------------------------------------------------
          // Raw result is mandatory.
          //
          // Protected completion is either:
          //   - a valid protected result;
          //   - a security alarm;
          //   - protected path was already disabled.
          //--------------------------------------------------------
          if ((raw_result_seen_reg ||
               raw_data_out_valid) &&
              ((!protected_enabled_reg) ||
               protected_sec_alarm ||
               protected_result_seen_reg ||
               protected_data_out_valid)) begin

            rsp_seq <= request_seq_reg;

            rsp_flags <=
              ((raw_result_seen_reg ||
                raw_data_out_valid) ? 8'h01 : 8'h00) |
              ((protected_enabled_reg &&
                !protected_sec_alarm &&
                (protected_result_seen_reg ||
                 protected_data_out_valid)) ?
                8'h02 : 8'h00) |
              (protected_sec_alarm ? 8'h04 : 8'h00) |
              (((!protected_enabled_reg) ||
                protected_sec_alarm) ? 8'h08 : 8'h00);

            rsp_sec_status <= protected_sec_status;

            if (raw_data_out_valid)
              rsp_raw_out <= raw_data_out;
            else
              rsp_raw_out <= raw_result_reg;

            if (protected_enabled_reg &&
                !protected_sec_alarm &&
                (protected_result_seen_reg ||
                 protected_data_out_valid)) begin
              if (protected_data_out_valid)
                rsp_protected_out <= protected_data_out;
              else
                rsp_protected_out <= protected_result_reg;
            end else begin
              rsp_protected_out <= 128'd0;
            end

            state_reg <= ST_SEND_RESPONSE;
          end
        end

        //----------------------------------------------------------
        // Start serializer only when it is idle.
        //----------------------------------------------------------
        ST_SEND_RESPONSE: begin
          if (!rsp_busy) begin
            rsp_start <= 1'b1;
            state_reg <= ST_WAIT_RSP_BUSY;
          end
        end

        //----------------------------------------------------------
        // Ensure serializer accepted rsp_start.
        //----------------------------------------------------------
        ST_WAIT_RSP_BUSY: begin
          if (rsp_busy)
            state_reg <= ST_WAIT_RSP_DONE;
        end

        //----------------------------------------------------------
        // Wait for complete response transmission.
        //----------------------------------------------------------
        ST_WAIT_RSP_DONE: begin
          if (!rsp_busy)
            state_reg <= ST_IDLE;
        end

        //----------------------------------------------------------
        // Fail-safe recovery.
        //----------------------------------------------------------
        default: begin
          state_reg <= ST_IDLE;

          request_seq_reg <= 8'd0;
          protected_enabled_reg <= 1'b0;

          raw_result_seen_reg <= 1'b0;
          raw_result_reg <= 128'd0;

          protected_result_seen_reg <= 1'b0;
          protected_result_reg <= 128'd0;

          core_key <= 128'd0;
          core_data_in <= 128'd0;

          raw_key_valid <= 1'b0;
          raw_data_in_valid <= 1'b0;
          protected_key_valid <= 1'b0;
          protected_data_in_valid <= 1'b0;

          rsp_start <= 1'b0;
          rsp_seq <= 8'd0;
          rsp_flags <= 8'd0;
          rsp_sec_status <= 8'd0;
          rsp_raw_out <= 128'd0;
          rsp_protected_out <= 128'd0;
        end
      endcase
    end
  end

endmodule

`default_nettype wire
