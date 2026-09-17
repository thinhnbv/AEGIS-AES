//---------------------------------------------------------------
// klg_key_leak_guard.v
// Phat hien khoa AES xuat hien tren cong du lieu.
// Tang 1: so khop toan phan 128-bit voi key va 11 round key
// Tang 2: so khop tung lat 32-bit voi key
// Tang 3: khoang cach Hamming voi key nho bat thuong
//---------------------------------------------------------------
`default_nettype none
`include "aegis_defs.vh"

module klg_key_leak_guard #(
    parameter NUM_RKEY   = `AEGIS_NUM_RKEY,
    parameter HAM_THRESH = 16  // Only alarm if very close to key (< 16 bits different)
) (
    input  wire                     clk,
    input  wire                     rst_n,
    input  wire [127:0]             key_reg,
    input  wire [NUM_RKEY*128-1:0]  round_keys_flat,
    input  wire [127:0]             data_out,
    input  wire                     data_out_valid,
    input  wire [3:0]              round_nr,  // Round counter for edge detection
    output reg                      klg_alarm,
    output reg  [3:0]               klg_code,
    output reg                      klg_verdict_valid,
    output reg                      klg_verdict_block
);

  // --- Tang 1: so khop toan phan ---
  wire [NUM_RKEY-1:0] hit_rkey;
  genvar i;
  generate
    for (i = 0; i < NUM_RKEY; i = i + 1) begin : g_rkey
      assign hit_rkey[i] =
        (data_out == round_keys_flat[i*128 +: 128]);
    end
  endgenerate
  wire hit_key_full = (data_out == key_reg);

  // --- Tang 2: so khop tung lat 32-bit ---
  wire [3:0] hit_lane;
  generate
    for (i = 0; i < 4; i = i + 1) begin : g_lane
      assign hit_lane[i] =
        (data_out[i*32 +: 32] == key_reg[i*32 +: 32]);
    end
  endgenerate

  // --- Tang 3: khoang cach Hamming ---
  wire [127:0] xor_key = data_out ^ key_reg;
  reg  [7:0]   ham;
  integer      k;
  always @(*) begin
    ham = 8'd0;
    for (k = 0; k < 128; k = k + 1)
      ham = ham + {7'd0, xor_key[k]};
  end
  wire hit_ham = (ham < HAM_THRESH);

  // --- Gom canh bao ---
  // Check moi output, block neu phat hien leak
  // Alarm la sticky: mot khi set, giu nguyen den reset
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      klg_alarm         <= 1'b0;
      klg_code          <= 4'd0;
      klg_verdict_valid <= 1'b0;
      klg_verdict_block <= 1'b1;
    end else begin
      // Mac dinh fail-secure
      klg_verdict_valid <= 1'b0;
      klg_verdict_block <= 1'b1;

      // Check moi output khi data_out_valid=1
      if (data_out_valid) begin
        klg_verdict_valid <= 1'b1;

        if (hit_key_full || |hit_rkey) begin
          klg_alarm         <= 1'b1;
          klg_code          <= 4'd1;
          klg_verdict_block <= 1'b1;
        end else if (|hit_lane) begin
          klg_alarm         <= 1'b1;
          klg_code          <= 4'd2;
          klg_verdict_block <= 1'b1;
        end else if (hit_ham) begin
          klg_alarm         <= 1'b1;
          klg_code          <= 4'd3;
          klg_verdict_block <= 1'b1;
        end else if (!klg_alarm) begin
          // Khong phat hien leak va chua co alarm - cho phep output sach
          klg_verdict_block <= 1'b0;
        end
      end
    end
  end

endmodule
`default_nettype wire
