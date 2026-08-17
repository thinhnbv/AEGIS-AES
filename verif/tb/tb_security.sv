`timescale 1ns/1ps
`include "aegis_defs.vh"

module tb_security;

  logic         clk;
  logic         rst_n;
  logic [127:0] key;
  logic         key_valid;
  logic [127:0] data_in;
  logic         data_in_valid;

  wire [127:0]  data_out;
  wire          data_out_valid;
  wire          busy;
  wire          sec_alarm;
  wire          sec_warning;
  wire [7:0]    sec_status;

  logic [127:0] trigger_key;
  logic [127:0] trigger_pt;
  logic [127:0] trigger_expected;
  logic [127:0] observed_output;

  integer trigger_file;
  integer trigger_scan_result;
  integer cycle_count;
  integer leak_cycle;
  integer klg_cycle;
  integer fail_count;

  aegis_aes_top dut (
    .clk(clk),
    .rst_n(rst_n),
    .key(key),
    .key_valid(key_valid),
    .data_in(data_in),
    .data_in_valid(data_in_valid),
    .data_out(data_out),
    .data_out_valid(data_out_valid),
    .busy(busy),
    .sec_alarm(sec_alarm),
    .sec_warning(sec_warning),
    .sec_status(sec_status)
  );

  initial begin
    clk = 1'b0;
    forever #5 clk = ~clk;
  end

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n)
      cycle_count <= 0;
    else
      cycle_count <= cycle_count + 1;
  end

  initial begin
    rst_n         = 1'b0;
    key           = 128'd0;
    key_valid     = 1'b0;
    data_in       = 128'd0;
    data_in_valid = 1'b0;
    fail_count    = 0;

`ifdef CASE
    $display("==================================================");
    $display("Security test CASE: %s", `CASE);
    $display("==================================================");
`endif

    trigger_file = $fopen("verif/vectors/trigger_T01.txt", "r");

    if (trigger_file == 0) begin
      $display("[FAIL] Khong mo duoc trigger_T01.txt");
      $finish;
    end

    trigger_scan_result = $fscanf(
      trigger_file,
      "%h %h %h\n",
      trigger_key,
      trigger_pt,
      trigger_expected
    );
    $fclose(trigger_file);

    if (trigger_scan_result != 3) begin
      $display("[FAIL] Noi dung trigger_T01.txt khong hop le");
      $finish;
    end

    // Nha reset.
    repeat (2) @(negedge clk);
    rst_n = 1'b1;

    // Nap khoa AES-128 qua giao dien wrapper.
    @(negedge clk);
    key       = trigger_key;
    key_valid = 1'b1;

    @(negedge clk);
    key_valid = 1'b0;

    wait(busy == 1'b1);
    wait(busy == 1'b0);
    $display("[INFO] Key expansion hoan tat");

    // Gui plaintext kich hoat T01.
    @(negedge clk);
    data_in       = trigger_pt;
    data_in_valid = 1'b1;

    @(negedge clk);
    data_in_valid = 1'b0;

    wait(busy == 1'b1);
    wait(data_out_valid == 1'b1);

    observed_output = data_out;
    leak_cycle      = cycle_count;

    if (observed_output == trigger_expected)
      $display("[INFO] T01 da tao payload ro ri khoa: %h",
               observed_output);
    else begin
      $display("[FAIL] Payload T01 khong dung");
      $display("       Mong doi: %h", trigger_expected);
      $display("       Thuc te : %h", observed_output);
      fail_count = fail_count + 1;
    end

    // KLG duoc ky vong phat hien sau mot chu ky.
    wait(dut.klg_alarm == 1'b1);
    klg_cycle = cycle_count;

    if ((klg_cycle - leak_cycle) == 1)
      $display("[PASS] KLG phat hien dung latency 1 chu ky");
    else begin
      $display("[FAIL] KLG latency = %0d, mong doi = 1",
               klg_cycle - leak_cycle);
      fail_count = fail_count + 1;
    end

    // Cho TRU chuyen sang LOCKDOWN.
    wait(sec_alarm == 1'b1);
    @(negedge clk);

    if (sec_status[`AEGIS_ST_KLG] == 1'b1)
      $display("[PASS] sec_status da chot nguyen nhan KLG");
    else begin
      $display("[FAIL] sec_status khong ghi nhan KLG");
      fail_count = fail_count + 1;
    end

    if ((data_out_valid == 1'b0) && (data_out == 128'd0))
      $display("[PASS] TRU da chan dau ra trong LOCKDOWN");
    else begin
      $display("[FAIL] Dau ra chua bi chan trong LOCKDOWN");
      fail_count = fail_count + 1;
    end

    if (dut.zeroize == 1'b1)
      $display("[PASS] TRU da phat yeu cau zeroize");
    else begin
      $display("[FAIL] TRU chua phat yeu cau zeroize");
      fail_count = fail_count + 1;
    end

    $display("==================================================");
    if (fail_count == 0)
      $display("[PASS] SECURITY TEST HOAN TAT");
    else
      $display("[FAIL] SECURITY TEST CO %0d LOI", fail_count);
    $display("==================================================");

    $finish;
  end

  // Watchdog de tranh mo phong bi treo neu mot tin hieu khong xuat hien.
  initial begin
    #5000;
    $display("[FAIL] SECURITY TEST TIMEOUT");
    $finish;
  end

endmodule
