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
  // zeroize va klg_alarm accessed via hierarchical path

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
  integer round_idx;
  integer tap_fail_count;
  integer goto_summary;

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

  // Debug FSM state transitions
  reg [2:0] prev_state;
  always @(posedge clk) begin
    if (rst_n && (prev_state != dut.state)) begin
      $display("DEBUG FSM: state %0d -> %0d at cycle %0d", prev_state, dut.state, cycle_count);
      $display("DEBUG: core_ready=%b core_dvalid=%b busy=%b zeroize=%b sec_alarm=%b",
               dut.u_core.ready, dut.core_dvalid, busy, dut.zeroize, sec_alarm);
      $display("DEBUG: klg_alarm=%b rcm_alarm=%b klg_verdict_valid=%b klg_verdict_block=%b",
               dut.u_klg.klg_alarm, dut.u_rcm.rcm_alarm,
               dut.u_klg.klg_verdict_valid, dut.u_klg.klg_verdict_block);
      $display("DEBUG: result=%h", dut.core_dout);
      prev_state <= dut.state;
    end
  end
  initial prev_state = 3'd0;

  initial begin
    rst_n          = 1'b0;
    key            = 128'd0;
    key_valid      = 1'b0;
    data_in        = 128'd0;
    data_in_valid  = 1'b0;
    fail_count     = 0;
    tap_fail_count = 0;
    goto_summary   = 0;

`ifdef CASE
    $display("==================================================");
    $display("Security test CASE: %s", `CASE);
    $display("==================================================");
`endif

    trigger_file = $fopen({"verif/vectors/trigger_", `CASE, ".txt"}, "r");

    clean_file = $fopen("verif/vectors/fips197_appb.txt", "r");

    if (clean_file == 0) begin
      $display("[FAIL] Khong mo duoc fips197_appb.txt");
      $fatal(1, "Khong mo duoc fips197_appb.txt");
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
      $fatal(1, "Noi dung fips197_appb.txt khong hop le");
    end

    if (trigger_file == 0) begin
      $display("[FAIL] Khong mo duoc trigger_%s.txt", `CASE);
      $fatal(1, "Khong mo duoc trigger file");
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
      $display("[FAIL] Noi dung trigger_%s.txt khong hop le", `CASE);
      $fatal(1, "Noi dung trigger file khong hop le");
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

    #1;

    // Tham chieu phan cap chi dung trong testbench de doi chieu mapping.
    // RTL tong hop chi su dung cong round_keys_flat.
    for (round_idx = 0;
        round_idx < `AEGIS_NUM_RKEY;
        round_idx = round_idx + 1) begin
      if (dut.round_keys_flat[round_idx*128 +: 128] !==
          dut.u_core.keymem.key_mem[round_idx]) begin
        $display("[FAIL] Mapping round key %0d khong dung", round_idx);
        $display("       Tap     : %h",
                dut.round_keys_flat[round_idx*128 +: 128]);
        $display("       Key mem : %h",
                dut.u_core.keymem.key_mem[round_idx]);
        tap_fail_count = tap_fail_count + 1;
        fail_count     = fail_count + 1;
      end
    end

    if (tap_fail_count == 0)
      $display("[PASS] Cong tapped anh xa dung ca 11 round key AES-128");

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

    // Clean case: khong co Trojan, KLG/ORC khong bao dong
    // Dua vao day ngay sau phan kiem tra clean, khong gui trigger
    if ((`CASE == "clean") || (`CASE == "CLEAN") || (`CASE == "C")) begin
      // Clean case khong can doi them - test da hoan thanh o phia tren
      // Chi kiem tra khong co alarm
      if (sec_alarm === 1'b0)
        $display("[OK] Khong co canh bao (clean case)");
      else begin
        $display("[FAIL] Co canh bao nham (clean ne)");
        fail_count = fail_count + 1;
      end
      // Ket thuc test thanh cong cho clean case
      $display("==================================================");
      if (fail_count == 0) begin
        $display("[PASS] SECURITY TEST HOAN TAT");
        $display("==================================================");
      end else begin
        $display("[FAIL] SECURITY TEST CO %0d LOI", fail_count);
        $display("==================================================");
      end
      $finish;
    end

    // Gui trigger plaintext cho cac Trojan cases (T01, T02, T03)
    @(negedge clk);
    data_in       = trigger_pt;
    data_in_valid = 1'b1;

    @(negedge clk);
    data_in_valid = 1'b0;

    if ((`CASE == "T01_p1_key_dump") || (`CASE == "T01")) begin
      // T01: KLG phat hien key dump
      // ORC/RCM cung co the phat hien vi T01 tra ve key thay vi ket qua
      $display("[DEBUG T01] Bat dau test T01");

      // Doi sec_alarm voi timeout
      fork
        begin
          #10000;
          $display("[FAIL] T01 TIMEOUT: sec_alarm khong bao gio = 1");
          $display("       FSM state=%d busy=%b zeroize=%b klg_alarm=%b",
                   dut.state, busy, dut.zeroize, dut.u_klg.klg_alarm);
          fail_count = fail_count + 1;
        end
        begin
          wait(sec_alarm == 1'b1);
          $display("[DEBUG T01] sec_alarm=1 tai cycle %0d, FSM state=%d", cycle_count, dut.state);
        end
      join_any
      disable fork;

      // Kiem tra nguon canh bao
      if (sec_status[`AEGIS_ST_KLG]) begin
        $display("[PASS] KLG da phat hien Trojan T01");
      end else if (sec_status[`AEGIS_ST_ORC]) begin
        $display("[PASS] ORC da phat hien Trojan T01");
      end else begin
        $display("[FAIL] Khong co monitor nao phat hien Trojan");
        fail_count = fail_count + 1;
      end

      if (dut.zeroize == 1'b1)
        $display("[PASS] TRU da phat yeu cau zeroize");
      else begin
        $display("[FAIL] TRU chua phat yeu cau zeroize");
        fail_count = fail_count + 1;
      end

      // Doi zeroize hoan tat
      repeat(5) @(posedge clk);
      #1;

      if (dut.key_reg === 128'd0)
        $display("[PASS] Wrapper da xoa key_reg");
      else begin
        $display("[FAIL] Wrapper chua xoa key_reg: %h", dut.key_reg);
        fail_count = fail_count + 1;
      end

      if (dut.round_keys_flat === {(`AEGIS_NUM_RKEY * 128){1'b0}})
        $display("[PASS] AES core da xoa 11 round key");
      else begin
        $display("[FAIL] AES core chua xoa het 11 round key");
        fail_count = fail_count + 1;
      end

      if ((data_out === 128'd0) || (data_out_valid === 1'b0))
        $display("[PASS] Output bi chan trong khi zeroization");
      else begin
        $display("[FAIL] Output khong an toan trong khi zeroization");
        fail_count = fail_count + 1;
      end
    end else if ((`CASE == "T02_p2_slow_leak") || (`CASE == "T02") ||
                 (`CASE == "T03_p3_skip_mixcol") || (`CASE == "T03")) begin
      // T02/T03: ORC/RCM phat hien Trojan
      // ORC/RCM trigger zeroize ngay khi phat hien bat thuong
      $display("[DEBUG] Bat dau test T02/T03");
      fork
        begin
          #10000;
          $display("[FAIL] T02/T03 TIMEOUT: sec_alarm khong bao gio = 1");
          fail_count = fail_count + 1;
        end
        begin
          wait(sec_alarm == 1'b1);
          $display("[DEBUG] sec_alarm=1 tai cycle %0d", cycle_count);
        end
      join_any
      disable fork;

      @(negedge clk);
      #1;

      // Kiem tra ORC/RCM da phat hien
      if (sec_status[`AEGIS_ST_ORC]) begin
        $display("[PASS] ORC da phat hien Trojan %s", `CASE);
      end else if (sec_status[`AEGIS_ST_RCM]) begin
        $display("[PASS] RCM da phat hien Trojan %s", `CASE);
      end else begin
        $display("[FAIL] Khong co monitor nao phat hien Trojan");
        $display("       sec_status=%b", sec_status);
        fail_count = fail_count + 1;
      end

      if (dut.zeroize == 1'b1)
        $display("[PASS] TRU da phat yeu cau zeroize");
      else begin
        $display("[FAIL] TRU chua phat yeu cau zeroize");
        fail_count = fail_count + 1;
      end

      // Doi zeroize hoan tat
      repeat(5) @(posedge clk);
      #1;

      if (dut.key_reg === 128'd0)
        $display("[PASS] Wrapper da xoa key_reg");
      else begin
        $display("[FAIL] Wrapper chua xoa key_reg: %h", dut.key_reg);
        fail_count = fail_count + 1;
      end

      if (dut.round_keys_flat === {(`AEGIS_NUM_RKEY * 128){1'b0}})
        $display("[PASS] AES core da xoa 11 round key");
      else begin
        $display("[FAIL] AES core chua xoa het 11 round key");
        fail_count = fail_count + 1;
      end

      if ((data_out_valid === 1'b0) && (data_out === 128'd0))
        $display("[PASS] Output bi chan trong khi zeroization");
      else begin
        $display("[FAIL] Output khong an toan trong khi zeroization");
        fail_count = fail_count + 1;
      end
    end

    // --- TOM TAT ---
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
    $fatal(1, "SECURITY TEST TIMEOUT");
  end

endmodule
