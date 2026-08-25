//---------------------------------------------------------------
// aegis_aes_top.v
// Wrapper chuyen giao thuc don gian sang giao thuc cua secworks/aes.
//---------------------------------------------------------------
`default_nettype none
`include "aegis_defs.vh"

module aegis_aes_top #(
    parameter EN_ORC = 1
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
  localparam ST_WAIT_RESULT_LOW  = 3'd4;
  localparam ST_WAIT_RESULT_HIGH = 3'd5;

  reg [2:0] state;

  reg [127:0] key_reg;
  reg [127:0] block_reg;
  reg         core_init;
  reg         core_next;
  reg         busy_reg;

  wire         core_ready;
  wire [127:0] core_dout;
  wire         core_dvalid;
  wire         core_result_new;

  // AES-128: keylen = 0, encdec = 1.
  // Lap lai khoa o hai nua de tranh nham mapping cua secworks/aes.
  aes_core u_core (
    .clk(clk),
    .reset_n(rst_n),
    .encdec(1'b1),
    .init(core_init),
    .next(core_next),
    .ready(core_ready),
    .key({key_reg, key_reg}),
    .keylen(1'b0),
    .block(block_reg),
    .result(core_dout),
    .result_valid(core_dvalid)
  );

  // Tap 11 round key AES-128 trong mo phong.
  // Tham chieu phan cap nay khong dung duoc khi tong hop FPGA/ASIC.
  wire [`AEGIS_NUM_RKEY*128-1:0] round_keys_flat;

  assign round_keys_flat = {
    u_core.keymem.key_mem[10],
    u_core.keymem.key_mem[9],
    u_core.keymem.key_mem[8],
    u_core.keymem.key_mem[7],
    u_core.keymem.key_mem[6],
    u_core.keymem.key_mem[5],
    u_core.keymem.key_mem[4],
    u_core.keymem.key_mem[3],
    u_core.keymem.key_mem[2],
    u_core.keymem.key_mem[1],
    u_core.keymem.key_mem[0]
  };

  wire       klg_alarm;
  wire [3:0] klg_code;
  wire       klg_verdict_valid;
  wire       klg_verdict_block;

  // Tao mot xung lay mau cho moi ket qua moi cua AES core.
  // FSM roi ST_WAIT_RESULT_HIGH ngay sau canh nhan ket qua dau tien.
  assign core_result_new =
    (state == ST_WAIT_RESULT_HIGH) && core_dvalid;

  klg_key_leak_guard #(
    .NUM_RKEY(`AEGIS_NUM_RKEY)
  ) u_klg (
    .clk(clk),
    .rst_n(rst_n),
    .key_reg(key_reg),
    .round_keys_flat(round_keys_flat),
    .data_out(core_dout),
    .data_out_valid(core_result_new),
    .klg_alarm(klg_alarm),
    .klg_code(klg_code),
    .klg_verdict_valid(klg_verdict_valid),
    .klg_verdict_block(klg_verdict_block)
  );

  wire       zeroize;
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
    .rcm_alarm(1'b0),
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
      state      <= ST_IDLE;
      key_reg    <= 128'd0;
      block_reg  <= 128'd0;
      core_init  <= 1'b0;
      core_next  <= 1'b0;
      busy_reg   <= 1'b0;
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

          if (core_dvalid) begin
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
