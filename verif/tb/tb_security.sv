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
  logic [127:0] clean_key;
  logic [127:0] clean_pt;
  logic [127:0] clean_expected;
  logic [127:0] clean_internal_output;
  logic [127:0] internal_payload;

  integer clean_file;
  integer clean_scan_result;
  integer trigger_file;
  integer trigger_scan_result;
  integer cycle_count;
  integer payload_cycle;
  integer clean_payload_cycle;
  integer clean_output_cycle;
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

    clean_file = $fopen("verif/vectors/fips197_appb.txt", "r");

    if (clean_file == 0) begin
      $display("[FAIL] Khong mo duoc fips197_appb.txt");
      $finish;
    end

    clean_scan_result = $fscanf(
      clean_file,
      "%h %h %h\n",
      clean_key,
      clean_pt,
      clean_expected
    );
    $fclose(clean_file);

    if (clean_scan_result != 3) begin
      $display("[FAIL] Noi dung fips197_appb.txt khong hop le");
      $finish;
    end

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

    if (clean_key !== trigger_key) begin
      $fatal(1, "Vector sach va T01 phai dung cung khoa");
    end
    rst_n = 1'b1;

    // Nap khoa AES-128 qua giao dien wrapper.
    @(negedge clk);
    key       = clean_key;
    key_valid = 1'b1;

    @(negedge clk);
    key_valid = 1'b0;

    wait(busy == 1'b1);
    wait(busy == 1'b0);
    $display("[INFO] Key expansion hoan tat");

    // Gui mot plaintext sach truoc de kiem tra duong release.
    @(negedge clk);
    data_in       = clean_pt;
    data_in_valid = 1'b1;

    @(negedge clk);
    data_in_valid = 1'b0;

    wait(busy == 1'b1);
    wait(dut.core_dvalid == 1'b1);
    #1;

    clean_internal_output = dut.core_dout;
    clean_payload_cycle   = cycle_count;

    if (clean_internal_output === clean_expected)
      $display("[PASS] Core tao dung ciphertext sach: %h",
               clean_internal_output);
    else begin
      $display("[FAIL] Ciphertext sach noi bo khong dung");
      $display("       Mong doi: %h", clean_expected);
      $display("       Thuc te : %h", clean_internal_output);
      fail_count = fail_count + 1;
    end

    if ((data_out_valid === 1'b0) && (data_out === 128'd0))
      $display("[PASS] Output sach bi giu trong khi cho verdict");
    else begin
      $display("[FAIL] Output sach xuat hien truoc verdict");
      $display("       data_out_valid: %b", data_out_valid);
      $display("       data_out      : %h", data_out);
      fail_count = fail_count + 1;
    end

    wait(dut.klg_verdict_valid == 1'b1);
    #1;
    clean_output_cycle = cycle_count;

    if (dut.klg_alarm === 1'b0)
      $display("[PASS] KLG khong bao dong voi ciphertext sach");
    else begin
      $display("[FAIL] KLG bao dong nham voi ciphertext sach");
      fail_count = fail_count + 1;
    end

    if ((clean_output_cycle - clean_payload_cycle) == 1)
      $display("[PASS] Ciphertext sach duoc phat sau 1 chu ky");
    else begin
      $display("[FAIL] Latency output sach = %0d, mong doi = 1",
               clean_output_cycle - clean_payload_cycle);
      fail_count = fail_count + 1;
    end

    if ((data_out_valid === 1'b1) &&
        (data_out === clean_expected))
      $display("[PASS] Wrapper phat dung ciphertext sach");
    else begin
      $display("[FAIL] Wrapper khong phat dung ciphertext sach");
      $display("       data_out_valid: %b", data_out_valid);
      $display("       Mong doi      : %h", clean_expected);
      $display("       Thuc te       : %h", data_out);
      fail_count = fail_count + 1;
    end

    @(posedge clk);
    #1;

    if ((data_out_valid === 1'b0) &&
        (data_out === 128'd0) &&
        (dut.core_dvalid === 1'b1))
      $display("[PASS] Valid chi keo dai 1 chu ky, core_dvalid van cao");
    else begin
      $display("[FAIL] Output sach khong dong lai dung sau 1 chu ky");
      $display("       data_out_valid: %b", data_out_valid);
      $display("       data_out      : %h", data_out);
      $display("       core_dvalid   : %b", dut.core_dvalid);
      fail_count = fail_count + 1;
    end

    // Gui plaintext kich hoat T01 sau transaction sach.
    @(negedge clk);
    data_in       = trigger_pt;
    data_in_valid = 1'b1;

    @(negedge clk);
    data_in_valid = 1'b0;

    wait(busy == 1'b1);
    wait(dut.core_dvalid == 1'b0);
    wait(dut.core_dvalid == 1'b1);
    #1;

    internal_payload = dut.core_dout;
    payload_cycle    = cycle_count;

    if (internal_payload === trigger_expected)
      $display("[INFO] T01 da tao payload noi bo: %h",
               internal_payload);
    else begin
      $display("[FAIL] Payload noi bo T01 khong dung");
      $display("       Mong doi: %h", trigger_expected);
      $display("       Thuc te : %h", internal_payload);
      fail_count = fail_count + 1;
    end

    if ((data_out_valid === 1'b0) && (data_out === 128'd0))
      $display("[PASS] Quarantine da giu payload khoi cong ngoai");
    else begin
      $display("[FAIL] Payload da thoat ra cong ngoai truoc verdict");
      $display("       data_out_valid: %b", data_out_valid);
      $display("       data_out      : %h", data_out);
      fail_count = fail_count + 1;
    end

    // KLG duoc ky vong phat hien sau mot chu ky.
    wait(dut.klg_alarm == 1'b1);
    klg_cycle = cycle_count;

    if ((klg_cycle - payload_cycle) == 1)
      $display("[PASS] KLG phat hien dung latency 1 chu ky");
    else begin
      $display("[FAIL] KLG latency = %0d, mong doi = 1",
               klg_cycle - payload_cycle);
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
    if (fail_count == 0) begin
      $display("[PASS] SECURITY TEST HOAN TAT");
      $display("==================================================");
      $finish;
    end else begin
      $display("[FAIL] SECURITY TEST CO %0d LOI", fail_count);
      $display("==================================================");
      $fatal(1, "SECURITY TEST THAT BAI");
    end
  end

  // Watchdog de tranh mo phong bi treo neu mot tin hieu khong xuat hien.
  initial begin
    #5000;
    $display("[FAIL] SECURITY TEST TIMEOUT");
    $finish;
  end

endmodule
