//---------------------------------------------------------------
// tru_tamper_response.v
// FSM ba trang thai: NORMAL -> SUSPECT -> LOCKDOWN
// Chi thoat LOCKDOWN bang reset cung.
//---------------------------------------------------------------
`default_nettype none
`include "aegis_defs.vh"

module tru_tamper_response #(
    parameter WARN_LIMIT = 4
) (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        klg_alarm,
    input  wire        klg_verdict_valid,
    input  wire        klg_verdict_block,
    input  wire        fic_alarm,
    input  wire        rcm_alarm,
    input  wire        orc_alarm,
    input  wire        red_warning,
    output reg         sec_alarm,
    output reg         sec_warning,
    output reg  [7:0]  sec_status,
    output reg         zeroize,
    output reg         block_output
);

  reg [1:0] state;
  reg [3:0] warn_cnt;

  wire hard_alarm = klg_alarm | fic_alarm | rcm_alarm | orc_alarm;

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state        <= `AEGIS_NORMAL;
      warn_cnt     <= 4'd0;
      sec_alarm    <= 1'b0;
      sec_warning  <= 1'b0;
      sec_status   <= 8'd0;
      zeroize      <= 1'b0;
    end else begin
      case (state)
        `AEGIS_NORMAL: begin
          if (hard_alarm)
            state <= `AEGIS_LOCKDOWN;
          else if (red_warning) begin
            state       <= `AEGIS_SUSPECT;
            warn_cnt    <= 4'd1;
            sec_warning <= 1'b1;
          end
        end

        `AEGIS_SUSPECT: begin
          if (hard_alarm)
            state <= `AEGIS_LOCKDOWN;
          else if (red_warning) begin
            warn_cnt <= warn_cnt + 4'd1;
            if ((warn_cnt + 4'd1) >= WARN_LIMIT)
              state <= `AEGIS_LOCKDOWN;
          end
        end

        `AEGIS_LOCKDOWN: begin
          sec_alarm    <= 1'b1;
          zeroize      <= 1'b1;
        end

        default: state <= `AEGIS_LOCKDOWN;
      endcase

      // Ma nguyen nhan duoc chot cho den khi reset.
      if (klg_alarm)
        sec_status[`AEGIS_ST_KLG] <= 1'b1;
      if (fic_alarm)
        sec_status[`AEGIS_ST_FIC] <= 1'b1;
      if (rcm_alarm)
        sec_status[`AEGIS_ST_RCM] <= 1'b1;
      if (red_warning)
        sec_status[`AEGIS_ST_RED] <= 1'b1;
      if (orc_alarm)
        sec_status[`AEGIS_ST_ORC] <= 1'b1;
    end
  end


  // Mac dinh chan dau ra. Chi verdict sach trong NORMAL moi duoc mo.
  // Cac comparator KLG deu dung truoc thanh ghi verdict.
  always @(*) begin
    block_output = 1'b1;

    if (rst_n &&
        (state == `AEGIS_NORMAL) &&
        klg_verdict_valid &&
        !klg_verdict_block &&
        !hard_alarm)
      block_output = 1'b0;
  end
endmodule

`default_nettype wire
