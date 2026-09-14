//---------------------------------------------------------------
// aegis_aes_top.v
// Wrapper chuyen giao thuc don gian sang giao thuc cua secworks/aes.
//---------------------------------------------------------------
`default_nettype none
`include "aegis_defs.vh"

module aegis_aes_top #(
    parameter EN_ORC = 1,
    parameter EN_RCM = 1
) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire [127:0] key,
    input  wire         key_valid,
    input  wire [127:0] data_in,
    input  wire         data_in_valid,
    output wire [127:0] data_out,
    output wire         data_out_valid,
    output wire         busy,
    output wire         sec_alarm,
    output wire         sec_warning,
    output wire [7:0]   sec_status
);

  localparam ST_IDLE             = 3'd0;
  localparam ST_WAIT_KEY_BUSY    = 3'd1;
  localparam ST_WAIT_KEY_DONE    = 3'd2;
  localparam ST_READY            = 3'd3;
  localparam ST_WAIT_RESULT      = 3'd4;

  reg [2:0] state;

  reg [127:0] key_reg;
  reg [127:0] block_reg;
  reg         core_init;
  reg         core_next;
  reg         busy_reg;

  // Counter to wait for encryption to complete (AES needs ~50 cycles)
  reg [7:0] result_wait_cnt;

  wire         core_ready;
  wire [127:0] core_dout;
  wire         core_dvalid;
  wire         core_result_new;
  wire         zeroize;
  wire         core_reset_n;
  wire [`AEGIS_NUM_RKEY*128-1:0] round_keys_flat;

  // TRU giu AES core trong reset de xoa toan bo key schedule.
  assign core_reset_n = rst_n & ~zeroize;

  // AES-128: keylen = 0, encdec = 1.
  // Lap lai khoa o hai nua de tranh nham mapping cua secworks/aes.
  aes_core_tapped u_core (
    .clk(clk),
    .reset_n(core_reset_n),
    .encdec(1'b1),
    .init(core_init),
    .next(core_next),
    .ready(core_ready),
    .key({key_reg, key_reg}),
    .keylen(1'b0),
    .block(block_reg),
    .result(core_dout),
    .result_valid(core_dvalid),
    .round_keys_flat(round_keys_flat),
    .muxed_round_nr(core_round_nr)
  );

  wire       klg_alarm;
  wire [3:0] klg_code;
  wire       klg_verdict_valid;
  wire       klg_verdict_block;

  // RCM signals
  wire       rcm_alarm;
  wire [3:0] rcm_code;
  wire [3:0] core_round_nr;

  // Tao mot xung lay mau khi co ket qua AES moi.
  // Su dung core_dvalid_sync de track ket qua moi sau khi bat dau encryption.
  reg         core_dvalid_prev;
  reg         waiting_for_result;  // Flag when FSM starts waiting
  reg         core_dvalid_at_start;  // Sample of core_dvalid when we start waiting

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      core_dvalid_prev <= 1'b0;
      waiting_for_result <= 1'b0;
      core_dvalid_at_start <= 1'b0;
    end else begin
      core_dvalid_prev <= core_dvalid;

      if (state == ST_WAIT_RESULT && !waiting_for_result) begin
        // Just entered ST_WAIT_RESULT - sample current core_dvalid
        waiting_for_result <= 1'b1;
        core_dvalid_at_start <= core_dvalid;
      end else if (state != ST_WAIT_RESULT) begin
        // Left ST_WAIT_RESULT - reset flag
        waiting_for_result <= 1'b0;
      end
    end
  end

  // Pulse when core_dvalid changes from the value it had when we started waiting
  assign core_result_new =
    waiting_for_result &&
    (core_dvalid != core_dvalid_at_start);

  // Signal to clear KLG verdict at start of new encryption
  wire new_transaction = core_next;

  klg_key_leak_guard #(
    .NUM_RKEY(`AEGIS_NUM_RKEY)
  ) u_klg (
    .clk(clk),
    .rst_n(rst_n),
    .new_transaction(new_transaction),
    .key_reg(key_reg),
    .round_keys_flat(round_keys_flat),
    .data_out(core_dout),
    .data_out_valid(core_result_new),
    .klg_alarm(klg_alarm),
    .klg_code(klg_code),
    .klg_verdict_valid(klg_verdict_valid),
    .klg_verdict_block(klg_verdict_block)
  );

  // RCM - Round Consistency Monitor
  generate
    if (EN_RCM) begin : gen_rcm
      rcm_round_monitor #(
        .NUM_ROUNDS(10)
      ) u_rcm (
        .clk(clk),
        .rst_n(rst_n),
        .init(core_init),
        .next(core_next),
        .ready(core_ready),
        .result_valid(core_dvalid),
        .round_nr(core_round_nr),
        .rcm_alarm(rcm_alarm),
        .rcm_code(rcm_code)
      );
    end else begin : gen_rcm_stub
      assign rcm_alarm = 1'b0;
      assign rcm_code  = 4'd0;
    end
  endgenerate

  wire       block_output;
  wire       sec_alarm_int;
  wire       sec_warning_int;
  wire [7:0] sec_status_int;

  tru_tamper_response u_tru (
    .clk(clk),
    .rst_n(rst_n),
    .klg_alarm(klg_alarm),
    .klg_verdict_valid(klg_verdict_valid),
    .klg_verdict_block(klg_verdict_block),
    .fic_alarm(1'b0),
    .rcm_alarm(rcm_alarm),
    .orc_alarm(1'b0),
    .red_warning(1'b0),
    .sec_alarm(sec_alarm_int),
    .sec_warning(sec_warning_int),
    .sec_status(sec_status_int),
    .zeroize(zeroize),
    .block_output(block_output)
  );

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state            <= ST_IDLE;
      key_reg         <= 128'd0;
      block_reg       <= 128'd0;
      core_init       <= 1'b0;
      core_next       <= 1'b0;
      busy_reg        <= 1'b0;
      result_wait_cnt <= 6'd0;
    end else if (zeroize) begin
      state      <= ST_IDLE;
      key_reg    <= 128'd0;
      block_reg  <= 128'd0;
      core_init  <= 1'b0;
      core_next  <= 1'b0;
      busy_reg   <= 1'b1;
    end else begin
      // init va next chi duoc phat trong mot chu ky.
      core_init <= 1'b0;
      core_next <= 1'b0;

      case (state)
        ST_IDLE: begin
          busy_reg <= 1'b0;

          if (key_valid) begin
            key_reg   <= key;
            core_init <= 1'b1;
            busy_reg  <= 1'b1;
            state     <= ST_WAIT_KEY_BUSY;
          end
        end

        ST_WAIT_KEY_BUSY: begin
          busy_reg <= 1'b1;

          if (!core_ready)
            state <= ST_WAIT_KEY_DONE;
        end

        ST_WAIT_KEY_DONE: begin
          busy_reg <= 1'b1;

          if (core_ready) begin
            busy_reg <= 1'b0;
            state    <= ST_READY;
          end
        end

        ST_READY: begin
          busy_reg <= 1'b0;

          if (key_valid) begin
            key_reg   <= key;
            core_init <= 1'b1;
            busy_reg  <= 1'b1;
            state     <= ST_WAIT_KEY_BUSY;
          end else if (data_in_valid) begin
            block_reg       <= data_in;
            core_next      <= 1'b1;
            busy_reg       <= 1'b1;
            result_wait_cnt <= 6'd0;  // Reset counter
            state          <= ST_WAIT_RESULT;
          end
        end

        ST_WAIT_RESULT: begin
          busy_reg       <= 1'b1;
          result_wait_cnt <= result_wait_cnt + 6'd1;

          // Wait for AES to complete (~50 cycles for AES-128)
          // Then transition to READY to accept new transactions
          if (result_wait_cnt >= 6'd60) begin
            busy_reg <= 1'b0;
            state    <= ST_READY;
          end
        end

        default: begin
          state    <= ST_IDLE;
          busy_reg <= 1'b0;
        end
      endcase
    end
  end

  // data_out_valid pulse mot chu ky khi co ket qua hop le tu KLG.
  // result_pulsed chi duoc clear khi FSM chuyen sang trang thai moi.
  // Dung result_wait_cnt de dam bao da co ket qua.
  reg       data_out_valid_reg;
  reg [7:0] result_valid_cnt;
  reg       result_pulsed;
  reg [2:0] prev_fsm_state;
  reg       klg_block_prev;  // Delayed version of klg_verdict_block

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      data_out_valid_reg <= 1'b0;
      result_valid_cnt   <= 8'd0;
      result_pulsed     <= 1'b0;
      prev_fsm_state    <= 3'd0;
      klg_block_prev    <= 1'b1;
    end else begin
      prev_fsm_state <= state;
      klg_block_prev <= klg_verdict_block;

      // Clear result_pulsed when FSM leaves ST_WAIT_RESULT (new transaction)
      if (state != ST_WAIT_RESULT && prev_fsm_state == ST_WAIT_RESULT)
        result_pulsed <= 1'b0;

      // Set data_out_valid once per encryption
      // Use klg_block_prev to get the verdict from previous cycle
      if (!result_pulsed && state == ST_WAIT_RESULT && result_wait_cnt >= 6'd1 && !klg_block_prev) begin
        data_out_valid_reg <= 1'b1;
        result_pulsed     <= 1'b1;
        result_valid_cnt   <= 8'd0;
      end else if (result_valid_cnt >= 8'd1) begin
        // Clear after one cycle
        data_out_valid_reg <= 1'b0;
        result_valid_cnt   <= result_valid_cnt + 8'd1;
      end else begin
        data_out_valid_reg <= 1'b0;
        result_valid_cnt   <= result_valid_cnt + 8'd1;
      end
    end
  end

  assign data_out = block_output ? 128'd0 : core_dout;
  assign data_out_valid = data_out_valid_reg;

  assign busy        = busy_reg;
  assign sec_alarm   = sec_alarm_int;
  assign sec_warning = sec_warning_int;
  assign sec_status  = sec_status_int;

endmodule

`default_nettype wire
