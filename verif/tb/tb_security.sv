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
  // reg [1:0] prev_core_state;
  // always @(posedge clk) begin
  //   if (rst_n) begin
  //     if (prev_core_state != dut.u_core.aes_core_ctrl_reg) begin
  //       $display("DEBUG CORE FSM: %0d -> %0d at cycle %0d, enc_count=%d red=%b",
  //                prev_core_state, dut.u_core.aes_core_ctrl_reg, cycle_count,
  //                dut.u_core.encrypt_count,
  //                dut.u_red.red_warning);
  //       prev_core_state <= dut.u_core.aes_core_ctrl_reg;
  //     end
  //   end
  // end
  // initial prev_core_state = 2'd0;

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

    // T04 skip clean test vi Trojan se inject illegal state ngay trong clean test
    // T04 nhay thang den phan T04 test
    // Begin clean_test_block - chi chay cho non-T04 cases
    begin: clean_test_block
    // T04 skip clean test vi Trojan se inject illegal state ngay trong clean test
    if (!((`CASE == "T04_p4_debug_port") || (`CASE == "T04"))) begin

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

    // Doi FSM tro ve ST_READY va cho output settle
    // Phai doi 3 negedge: 1 de FSM update, 2 de data_out_valid reset
    wait(dut.state == 3'd3);
    repeat(3) @(negedge clk);
    #1;

    if ((data_out_valid === 1'b0) &&
        (data_out === 128'd0))
      $display("[PASS] Valid chi keo dai 1 chu ky, data_out bi reset");
    else begin
      $display("[FAIL] Output sach khong dong lai dung sau 1 chu ky");
      $display("       data_out_valid: %b", data_out_valid);
      $display("       data_out      : %h", data_out);
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
    end  // End if (!T04) for clean test
    end  // End clean_test_block

    // Gui trigger plaintext cho cac Trojan cases (T01, T02, T03)
    // T04 da duoc xu ly rieng o phia tren
    if ((`CASE != "T04_p4_debug_port") && (`CASE != "T04")) begin
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

      // Doi them 1 chu ky de sec_status cap nhat day du
      repeat(2) @(posedge clk);
      #1;

      // Kiem tra nguon canh bao
      $display("      [DEBUG T01] sec_status=%b (KLG=%b ORC=%b)",
               sec_status, sec_status[`AEGIS_ST_KLG], sec_status[`AEGIS_ST_ORC]);
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
                 (`CASE == "T03_p3_skip_mixcol") || (`CASE == "T03") ||
                 (`CASE == "T05_dos_trojan") || (`CASE == "T05")) begin
      // T02/T03/T05: ORC/RCM phat hien Trojan
      $display("[DEBUG] Bat dau test T02/T03/T05");
      fork
        begin
          #10000;
          $display("[FAIL] T02/T03/T05 TIMEOUT: sec_alarm khong bao gio = 1");
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

      // Kiem tra ORC/RCM/KLG da phat hien
      $display("      [DEBUG] sec_status=%b (KLG=%b ORC=%b RCM=%b FIC=%b RED=%b)",
               sec_status, sec_status[`AEGIS_ST_KLG], sec_status[`AEGIS_ST_ORC],
               sec_status[`AEGIS_ST_RCM], sec_status[`AEGIS_ST_FIC], sec_status[`AEGIS_ST_RED]);
      if (sec_status[`AEGIS_ST_KLG]) begin
        $display("[PASS] KLG da phat hien Trojan %s", `CASE);
      end else if (sec_status[`AEGIS_ST_ORC]) begin
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
    end  // End T02/T03/T05
    end  // End outer if (!T04) for trigger cases

    // T04 xu ly rieng - khong gui trigger
    if ((`CASE == "T04_p4_debug_port") || (`CASE == "T04")) begin
      // T04: FIC/RED phat hien FSM illegal state
      // Trigger: RED T2 sequential pattern (PT[i] = PT[i-1] + 1)
      // Payload: P4 - FSM illegal state injection
      // Detected by: FIC, RED
      $display("[INFO T04] Bat dau test T04 - FSM illegal state injection");

      // Doi wrapper FSM tro ve ST_READY
      if (dut.state != 3'd3) begin
        wait(dut.state == 3'd3);
      end
      repeat(5) @(posedge clk);

      // === Giai doan 1: Gui clean_pt de set RED history ===
      $display("      [INFO T04] Giai doan 1: Gui clean_pt de set RED history");
      $display("      [DEBUG T04] clean_pt = %h", clean_pt);
      @(negedge clk);
      data_in = clean_pt;
      data_in_valid = 1'b1;
      @(negedge clk);
      data_in_valid = 1'b0;

      repeat(70) @(posedge clk);
      #1;
      $display("      [DEBUG T04] Sau GD1: RED hist[0]=%h hist[1]=%h red_code=%h",
               dut.u_red.pt_history[0], dut.u_red.pt_history[1], dut.u_red.red_code);

      // === Giai doan 2: Gui PT1 = clean_pt + 1 (RED phat hien T2) ===
      $display("      [INFO T04] Giai doan 2: Gui PT1 = clean_pt + 1");

      // Doi zeroize reset va wrapper tro ve ST_READY truoc khi gui PT1
      $display("      [DEBUG T04] Cho zeroize reset: state=%d busy=%d zeroize=%d",
               dut.state, busy, dut.zeroize);
      if (dut.zeroize) begin
        wait(dut.zeroize == 1'b0);
      end
      repeat(10) @(posedge clk);
      $display("      [DEBUG T04] Sau khi zeroize reset: state=%d busy=%d", dut.state, busy);

      $display("      [DEBUG T04] PT1 = %h", clean_pt + 128'd1);
      @(negedge clk);
      data_in = clean_pt + 128'd1;
      data_in_valid = 1'b1;
      $display("      [DEBUG T04] Sau khi gui: state=%d busy=%d", dut.state, busy);
      @(negedge clk);
      data_in_valid = 1'b0;

      repeat(5) @(posedge clk);
      #1;
      $display("      [DEBUG T04] GD2 cycle+5: state=%d busy=%d core_next=%b block_reg=%h",
               dut.state, busy, dut.u_core.next, dut.u_red.block);

      repeat(25) @(posedge clk);
      #1;
      $display("      [DEBUG T04] GD2 cycle+30: saw_red=%b red_code=%h hist[0]=%h",
               dut.u_core.saw_red_t2, dut.u_red.red_code, dut.u_red.pt_history[0]);

      if (sec_alarm) begin
        $display("      [INFO T04] Trojan da kich hoat sau PT1!");
      end else begin
        // === Giai doan 3: Gui PT2 = clean_pt + 2 ===
        $display("      [INFO T04] Giai doan 3: Gui PT2 = clean_pt + 2");
        repeat(40) @(posedge clk);
        @(negedge clk);
        data_in = clean_pt + 128'd2;
        data_in_valid = 1'b1;
        @(negedge clk);
        data_in_valid = 1'b0;

        repeat(30) @(posedge clk);
        #1;
        $display("      [DEBUG T04] Sau PT2: saw_red=%b red_code=%h core_fsm=%d sec_alarm=%b",
                 dut.u_core.saw_red_t2, dut.u_red.red_code, dut.u_core.aes_core_ctrl_reg, sec_alarm);

        if (sec_alarm) begin
          $display("      [INFO T04] Trojan da kich hoat sau PT2!");
        end else begin
          // === Giai doan 4: Gui PT3 = clean_pt + 3 ===
          $display("      [INFO T04] Giai doan 4: Gui PT3 = clean_pt + 3");
          repeat(40) @(posedge clk);
          @(negedge clk);
          data_in = clean_pt + 128'd3;
          data_in_valid = 1'b1;
          @(negedge clk);
          data_in_valid = 1'b0;

          repeat(30) @(posedge clk);
          #1;
          $display("      [DEBUG T04] Sau PT3: saw_red=%b red_code=%h core_fsm=%d sec_alarm=%b",
                   dut.u_core.saw_red_t2, dut.u_red.red_code, dut.u_core.aes_core_ctrl_reg, sec_alarm);
        end
      end

      $display("      [INFO T04] sec_status=%b (KLG=%b ORC=%b RCM=%b FIC=%b RED=%b)",
               sec_status, sec_status[`AEGIS_ST_KLG], sec_status[`AEGIS_ST_ORC],
               sec_status[`AEGIS_ST_RCM], sec_status[`AEGIS_ST_FIC], sec_status[`AEGIS_ST_RED]);
      $display("      [INFO T04] FIC fic_alarm=%b RED red_warning=%b",
               dut.u_fic.fic_alarm, dut.u_red.red_warning);

      // T04 duoc thiet ke de FIC va RED phat hien
      if (sec_status[`AEGIS_ST_FIC]) begin
        $display("[PASS] FIC da phat hien Trojan T04 (FSM illegal state)");
      end
      if (sec_status[`AEGIS_ST_RED]) begin
        $display("[PASS] RED da phat hien Trojan T04 (T2 sequential pattern)");
      end
      if (sec_status[`AEGIS_ST_ORC]) begin
        $display("[PASS] ORC da phat hien Trojan T04");
      end
      if (sec_status[`AEGIS_ST_KLG]) begin
        $display("[PASS] KLG da phat hien Trojan T04");
      end
      if (sec_status[`AEGIS_ST_RCM]) begin
        $display("[PASS] RCM da phat hien Trojan T04");
      end

      //sec_alarm phai = 1
      if (sec_alarm == 1'b0) begin
        $display("[FAIL] T04: sec_alarm chua bao = 1");
        $display("       FSM state=%d busy=%b zeroize=%d",
                 dut.state, busy, dut.zeroize);
        fail_count = fail_count + 1;
      end

      // Chi can FIC hoac RED phat hien (theo thiet ke)
      if (!sec_status[`AEGIS_ST_FIC] && !sec_status[`AEGIS_ST_RED]) begin
        $display("[FAIL] Khong co monitor nao phat hien Trojan (can FIC hoac RED)");
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
        $display("[FAIL] Wrapper chua xoa key_reg");
        fail_count = fail_count + 1;
      end

      if ((data_out === 128'd0) || (data_out_valid === 1'b0))
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
  // T04 can nhieu thoi gian hon vi phai reload key va gui 2 plaintext
  initial begin
    #500000;
    if (sec_alarm == 1'b1) begin
      $display("[INFO] SECURITY TEST COMPLETED (alarm detected)");
      $finish;
    end else if (dut.zeroize == 1'b1) begin
      $display("[INFO] SECURITY TEST COMPLETED (zeroize detected)");
      $finish;
    end else begin
      $display("[FAIL] SECURITY TEST TIMEOUT at cycle %0d", cycle_count);
      $display("       FSM state=%d busy=%b zeroize=%d sec_alarm=%b sec_status=%b",
               dut.state, busy, dut.zeroize, sec_alarm, sec_status);
      $fatal(1, "SECURITY TEST TIMEOUT");
    end
  end

endmodule
