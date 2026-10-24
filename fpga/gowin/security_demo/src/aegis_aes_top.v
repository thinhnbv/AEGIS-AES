//---------------------------------------------------------------
// aegis_aes_top.v
// Wrapper chuyen giao thuc don gian sang giao thuc cua secworks/aes.
//---------------------------------------------------------------
`default_nettype none
`include "aegis_defs.vh"

module aegis_aes_top #(
    parameter EN_ORC = 1  // Enable ORC to detect Trojans
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
    // zeroize va klg_alarm la internal wires, truy cap qua hierarchical path
);

  localparam ST_IDLE             = 3'd0;
  localparam ST_WAIT_KEY_BUSY    = 3'd1;
  localparam ST_WAIT_KEY_DONE    = 3'd2;
  localparam ST_READY            = 3'd3;
  localparam ST_WAIT_RESULT_LOW  = 3'd4;
  localparam ST_WAIT_RESULT_HIGH = 3'd5;

  reg [2:0] state;
  reg [15:0] wait_result_counter;  // Timeout counter for stuck states

  reg [127:0] key_reg;
  reg [127:0] block_reg;
  reg         core_init;
  reg         core_next;
  reg         busy_reg;

  wire         core_ready;
  wire [127:0] core_dout;
  wire         core_dvalid;
  wire         core_result_new;
  wire         zeroize;
  wire         core_reset_n;
  wire [`AEGIS_NUM_RKEY*128-1:0] round_keys_flat;

  // RCM signals
  wire       rcm_alarm;
  wire [3:0] rcm_code;
  wire [3:0] core_round_nr;

  // ORC signals
  wire       orc_alarm;
  wire [3:0] orc_code;
  wire       orc_ref_valid;
  wire [127:0] orc_ref_result;
  wire [127:0] state_before_final;
  wire [127:0] final_round_key;

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
    .muxed_round_nr(core_round_nr),
    .state_before_final(state_before_final)
  );

  // Tap FSM state tu aes_core de FIC kiem tra
  wire [1:0] core_fsm_state;
  assign core_fsm_state = u_core.aes_core_ctrl_reg;

  wire       klg_alarm;
  wire [3:0] klg_code;
  wire       klg_verdict_valid;
  wire       klg_verdict_block;

  // FIC signals
  wire       fic_alarm;

  // RED signals
  wire       red_warning;
  wire [7:0] red_code;

  // Tao mot xung lay mau cho moi ket qua moi cua AES core.
  // FSM roi ST_WAIT_RESULT_HIGH ngay sau canh nhan ket qua dau tien.
  assign core_result_new =
    (state == ST_WAIT_RESULT_HIGH) && core_dvalid;

  klg_key_leak_guard #(
    .NUM_RKEY(`AEGIS_NUM_RKEY)
    // NOTE (fpga/gowin/security_demo only): klg_key_leak_guard.v in
    // this project's src/ has its layer-2 (word match) and layer-3
    // (Hamming distance) computations commented out to fit two full
    // AES cores on one GW5A-25A - see that file for details. T01 is
    // still caught in full by layer 1 (hit_full), unaffected here.
  ) u_klg (
    .clk(clk),
    .rst_n(rst_n),
    .key_reg(key_reg),
    .key_valid(key_valid),
    .round_keys_flat(round_keys_flat),
    .data_out(core_dout),
    .data_out_valid(core_dvalid),  // Check on every core output, not wrapper state
    .orc_ref_valid(orc_ref_valid),
    .orc_ref_result(orc_ref_result),
    .round_nr(core_round_nr),      // Round counter for edge detection
    .klg_alarm(klg_alarm),
    .klg_code(klg_code),
    .klg_verdict_valid(klg_verdict_valid),
    .klg_verdict_block(klg_verdict_block)
  );

  // Final round key (round 10 for AES-128)
  assign final_round_key = round_keys_flat[`AEGIS_NUM_RKEY*128 - 1 -: 128];

  // RED - Rare-Event Detector
  red_rare_event #(
    .RARE_THRESHOLD(16'hFFFF)
  ) u_red (
    .clk(clk),
    .rst_n(rst_n),
    .block(block_reg),
    .block_valid(core_next),
    .red_warning(red_warning),
    .red_code(red_code)
  );

  // RCM - Round Consistency Monitor
  //
  // RCM observes the AES core round/handshake behavior. When TRU
  // asserts zeroize, the AES core is asynchronously reset through
  // core_reset_n. RCM must use the same reset domain so that the
  // defensive reset itself is not misclassified as a new round fault.
  //
  // Any genuine RCM cause is latched by TRU before zeroize is asserted,
  // so resetting RCM here does not lose the original security cause.
  rcm_round_monitor #(
    .NUM_ROUNDS(10)
  ) u_rcm (
    .clk(clk),
    .rst_n(core_reset_n),
    .init(core_init),
    .next(core_next),
    .ready(core_ready),
    .result_valid(core_dvalid),
    .round_nr(core_round_nr),
    .rcm_alarm(rcm_alarm),
    .rcm_code(rcm_code)
  );

  // FIC - FSM Integrity Checker
  fic_fsm_integrity u_fic (
    .clk(clk),
    .rst_n(rst_n),
    .fsm_state(core_fsm_state),
    .fic_alarm(fic_alarm)
  );

  // ORC - Output Redundancy Checker
  generate
    if (EN_ORC) begin : gen_orc
      orc_output_checker #(
        .NUM_ROUNDS(10)
      ) u_orc (
        .clk(clk),
        .rst_n(rst_n),
        .next(core_next),
        .result_valid(core_result_new),
        .round_nr(core_round_nr),
        .state_before_final(state_before_final),
        .final_round_key(final_round_key),
        .core_result(core_dout),
        .orc_alarm(orc_alarm),
        .orc_code(orc_code),
        .orc_ref_valid(orc_ref_valid),
        .orc_ref_result(orc_ref_result)
      );
    end else begin : gen_orc_stub
      assign orc_alarm = 1'b0;
      assign orc_code  = 4'd0;
      assign orc_ref_valid  = 1'b0;
      assign orc_ref_result = 128'd0;
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
    .fic_alarm(fic_alarm),
    .rcm_alarm(rcm_alarm),
    .orc_alarm(orc_alarm),
    .red_warning(red_warning),
    .sec_alarm(sec_alarm_int),
    .sec_warning(sec_warning_int),
    .sec_status(sec_status_int),
    .zeroize(zeroize),
    .block_output(block_output)
  );

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state      <= ST_IDLE;
      key_reg    <= 128'd0;
      block_reg  <= 128'd0;
      core_init  <= 1'b0;
      core_next  <= 1'b0;
      busy_reg   <= 1'b0;
      wait_result_counter <= 16'd0;
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
            block_reg <= data_in;
            core_next <= 1'b1;
            busy_reg  <= 1'b1;
            state     <= ST_WAIT_RESULT_LOW;
          end
        end

        ST_WAIT_RESULT_LOW: begin
          busy_reg <= 1'b1;

          if (!core_dvalid)
            state <= ST_WAIT_RESULT_HIGH;
        end

        ST_WAIT_RESULT_HIGH: begin
          busy_reg <= 1'b1;
          wait_result_counter <= wait_result_counter + 16'd1;

          if (core_dvalid) begin
            busy_reg <= 1'b0;
            state    <= ST_READY;
            wait_result_counter <= 16'd0;
          end else if (zeroize) begin
            // Core bi treo (FSM illegal state), nhung zeroize da duoc kich hoat
            busy_reg <= 1'b1;
            state    <= ST_IDLE;
            wait_result_counter <= 16'd0;
          end else if (wait_result_counter >= 16'd1000) begin
            // Timeout: core_dvalid khong bao gio len sau 1000 chu ky
            busy_reg <= 1'b0;
            state    <= ST_IDLE;
            wait_result_counter <= 16'd0;
          end
        end

        default: begin
          state    <= ST_IDLE;
          busy_reg <= 1'b0;
        end
      endcase
    end
  end

  // TRU chi mo dau ra trong cua so verdict sach mot chu ky.
  assign data_out =
    block_output ? 128'd0 : core_dout;

  assign data_out_valid =
    block_output ? 1'b0 : core_dvalid;

  assign busy        = busy_reg;
  assign sec_alarm   = sec_alarm_int;
  assign sec_warning = sec_warning_int;
  assign sec_status  = sec_status_int;

endmodule

`default_nettype wire
