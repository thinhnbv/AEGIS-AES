//---------------------------------------------------------------
// fic_fsm_integrity.v
// FSM Integrity Checker - Phat hien bat thuong trong FSM cua AES core
//
// Kiem tra tinh toan ven cua FSM trong aes_core_tapped:
// - One-hot: fsm_state luon co dung 1 bit = 1
// - Valid transition: cac chuyen trang thai phai theo bang hop le
//   CTRL_IDLE(0) -> CTRL_INIT(1), CTRL_NEXT(2)
//   CTRL_INIT(1) -> CTRL_IDLE(0)
//   CTRL_NEXT(2) -> CTRL_IDLE(0)
//---------------------------------------------------------------
`default_nettype none
`include "aegis_defs.vh"

module fic_fsm_integrity (
    input wire        clk,
    input wire        rst_n,
    input wire [1:0]  fsm_state,     // aes_core_ctrl_reg
    output reg        fic_alarm
);

  // FSM state encoding (tu aes_core_tapped)
  localparam CTRL_IDLE  = 2'h0;
  localparam CTRL_INIT  = 2'h1;
  localparam CTRL_NEXT  = 2'h2;

  // FSM state encoding (mo rong voi illegal states)
  // 2'h3 duoc xu ly nhu illegal state

  //------------------------------------------------------------
  // Registers
  //------------------------------------------------------------
  reg [1:0] prev_fsm_state;
  reg       prev_valid;  // Danh dau trang thai truoc co hop le

  //------------------------------------------------------------
  // One-hot check
  //
  // FSM chi chap nhan 3 gia tri: 2'b00, 2'b01, 2'b10
  // Bit thu 3 (2'b11) la illegal
  //------------------------------------------------------------
  wire one_hot_valid;
  assign one_hot_valid = (fsm_state != 2'h3);

  //------------------------------------------------------------
  // Transition validation
  //
  // Bang chuyen trang thai hop le:
  // - CTRL_IDLE(0)  -> CTRL_INIT(1), CTRL_NEXT(2), hoac giu nguyen
  // - CTRL_INIT(1)  -> CTRL_IDLE(0), hoac giu nguyen
  // - CTRL_NEXT(2)  -> CTRL_IDLE(0), hoac giu nguyen
  // - Illegal state -> bat ky dau cung la loi
  //------------------------------------------------------------
  wire       trans_valid;
  reg        first_cycle;

  // Kiem tra chuyen trang thai hop le
  reg        idle_to_init;
  reg        idle_to_next;
  reg        init_to_idle;
  reg        next_to_idle;
  reg        state_stable;

  always @(*) begin
    // Mac dinh: khong co chuyen nao hop le
    idle_to_init = 1'b0;
    idle_to_next = 1'b0;
    init_to_idle = 1'b0;
    next_to_idle = 1'b0;
    state_stable = 1'b0;

    case (prev_fsm_state)
      CTRL_IDLE: begin
        if (fsm_state == CTRL_IDLE)
          state_stable = 1'b1;
        else if (fsm_state == CTRL_INIT)
          idle_to_init = 1'b1;
        else if (fsm_state == CTRL_NEXT)
          idle_to_next = 1'b1;
      end

      CTRL_INIT: begin
        if (fsm_state == CTRL_INIT)
          state_stable = 1'b1;
        else if (fsm_state == CTRL_IDLE)
          init_to_idle = 1'b1;
      end

      CTRL_NEXT: begin
        if (fsm_state == CTRL_NEXT)
          state_stable = 1'b1;
        else if (fsm_state == CTRL_IDLE)
          next_to_idle = 1'b1;
      end

      default: begin
        // Illegal previous state - bat ky chuyen nao deu la loi
      end
    endcase
  end

  assign trans_valid =
    state_stable || idle_to_init || idle_to_next ||
    init_to_idle || next_to_idle;

  //------------------------------------------------------------
  // Alarm logic
  //
  // fic_alarm bat khi:
  // - FSM khong con one-hot (fsm_state = 2'b11)
  // - Chuyen trang thai khong hop le
  // Alarm la sticky: chi xoa khi reset
  //------------------------------------------------------------
  wire alarm_condition;

  // Bao loi khi:
  // 1. FSM khong one-hot
  // 2. Chuyen trang thai khong hop le (sau chu ky dau tien)
  assign alarm_condition = !one_hot_valid || (!first_cycle && !trans_valid);

  // Sync prev_fsm_state va prev_valid
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      prev_fsm_state <= CTRL_IDLE;
      prev_valid     <= 1'b1;
      first_cycle    <= 1'b1;
    end else begin
      prev_fsm_state <= fsm_state;
      prev_valid     <= one_hot_valid;
      first_cycle    <= 1'b0;
    end
  end

  // Fic alarm - sticky
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      fic_alarm <= 1'b0;
    end else begin
      if (alarm_condition)
        fic_alarm <= 1'b1;
    end
  end

endmodule
`default_nettype wire
