`timescale 1ns/1ps
`include "aegis_defs.vh"

module tb_security;

  //------------------------------------------------------------
  // DUT interface.
  //------------------------------------------------------------
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


  //------------------------------------------------------------
  // Test vectors.
  //------------------------------------------------------------
  logic [127:0] trigger_key;
  logic [127:0] trigger_pt;
  logic [127:0] trigger_expected;

  logic [127:0] clean_key;
  logic [127:0] clean_pt;
  logic [127:0] clean_expected;
  logic [127:0] clean_internal_output;


  //------------------------------------------------------------
  // T04 sequence.
  //------------------------------------------------------------
  logic [127:0] t04_pt_a5;
  logic [127:0] t04_pt_5a;
  logic [127:0] t04_pt_ff;


  //------------------------------------------------------------
  // Expected detector mask.
  //
  // sec_status:
  //   bit 0 = KLG
  //   bit 1 = FIC
  //   bit 2 = RCM
  //   bit 3 = RED
  //   bit 4 = ORC
  //------------------------------------------------------------
  logic [7:0] expected_mask;


  //------------------------------------------------------------
  // Test state.
  //------------------------------------------------------------
  integer clean_file;
  integer clean_scan_result;

  integer trigger_file;
  integer trigger_scan_result;

  integer cycle_count;
  integer clean_payload_cycle;
  integer clean_output_cycle;

  integer fail_count;
  integer round_idx;
  integer tap_fail_count;
  integer wait_count;


  //------------------------------------------------------------
  // DUT.
  //------------------------------------------------------------
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


  //------------------------------------------------------------
  // Clock.
  //------------------------------------------------------------
  initial begin
    clk = 1'b0;
    forever #5 clk = ~clk;
  end


  //------------------------------------------------------------
  // Cycle counter.
  //------------------------------------------------------------
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n)
      cycle_count <= 0;
    else
      cycle_count <= cycle_count + 1;
  end


  //------------------------------------------------------------
  // Print detector state in ONE format for every Trojan.
  //------------------------------------------------------------
  task automatic print_detector_status;
    begin

      $display("--------------------------------------------------");
      $display("[SECURITY] CASE      : %s", `CASE);
      $display("[SECURITY] cycle     : %0d", cycle_count);
      $display("[SECURITY] sec_alarm : %b", sec_alarm);
      $display("[SECURITY] zeroize   : %b", dut.zeroize);

      $display(
        "[SECURITY] monitors  : KLG=%b FIC=%b RCM=%b RED=%b ORC=%b",
        sec_status[`AEGIS_ST_KLG],
        sec_status[`AEGIS_ST_FIC],
        sec_status[`AEGIS_ST_RCM],
        sec_status[`AEGIS_ST_RED],
        sec_status[`AEGIS_ST_ORC]
      );

      $display(
        "[SECURITY] sec_status: %08b",
        sec_status
      );

      $display(
        "[SECURITY] expected  : %08b",
        expected_mask
      );

      $display("--------------------------------------------------");

    end
  endtask


  //------------------------------------------------------------
  // Wait for TRU hard alarm.
  //------------------------------------------------------------
  task automatic wait_for_security_alarm;
    input integer max_cycles;
    begin

      wait_count = 0;

      while ((sec_alarm !== 1'b1) &&
             (wait_count < max_cycles)) begin

        @(posedge clk);
        wait_count = wait_count + 1;

      end


      if (sec_alarm !== 1'b1) begin

        $display(
          "[FAIL] %s: TIMEOUT, sec_alarm khong len",
          `CASE
        );

        fail_count = fail_count + 1;

      end
      else begin

        //-------------------------------------------------------
        // Give TRU/sec_status time to latch all detector causes.
        //-------------------------------------------------------
        repeat (2) @(posedge clk);
        #1;

      end

    end
  endtask


  //------------------------------------------------------------
  // Check that all REQUIRED detectors fired.
  //
  // Extra detectors are allowed and remain visible in sec_status.
  //------------------------------------------------------------
  task automatic check_expected_detectors;
    begin

      if ((sec_status & expected_mask) == expected_mask) begin

        $display(
          "[PASS] Expected monitors da bat dung cho %s",
          `CASE
        );

      end
      else begin

        $display(
          "[FAIL] Sai monitor cho %s: actual=%08b expected_mask=%08b",
          `CASE,
          sec_status,
          expected_mask
        );

        fail_count = fail_count + 1;

      end

    end
  endtask


  //------------------------------------------------------------
  // Common TRU / zeroization / output checks.
  //
  // Used by T01, T02, T03, T04 and T05.
  //------------------------------------------------------------
  task automatic check_common_security_response;
    begin

      print_detector_status();
      check_expected_detectors();


      if (sec_alarm === 1'b1)
        $display("[PASS] TRU da vao LOCKDOWN");
      else begin
        $display("[FAIL] TRU chua vao LOCKDOWN");
        fail_count = fail_count + 1;
      end


      if (dut.zeroize === 1'b1)
        $display("[PASS] TRU da phat zeroize");
      else begin
        $display("[FAIL] TRU chua phat zeroize");
        fail_count = fail_count + 1;
      end


      //---------------------------------------------------------
      // Let core reset / zeroization propagate.
      //---------------------------------------------------------
      repeat (5) @(posedge clk);
      #1;


      if (dut.key_reg === 128'd0)
        $display("[PASS] Wrapper da xoa key_reg");
      else begin
        $display(
          "[FAIL] Wrapper chua xoa key_reg: %h",
          dut.key_reg
        );
        fail_count = fail_count + 1;
      end


      if (dut.round_keys_flat ===
          {(`AEGIS_NUM_RKEY * 128){1'b0}})
        $display("[PASS] AES core da xoa 11 round key");
      else begin
        $display("[FAIL] AES core chua xoa het 11 round key");
        fail_count = fail_count + 1;
      end


      if ((data_out_valid === 1'b0) &&
          (data_out === 128'd0))
        $display("[PASS] Output da bi chan an toan");
      else begin
        $display("[FAIL] Output khong bi chan an toan");
        fail_count = fail_count + 1;
      end

    end
  endtask


  //------------------------------------------------------------
  // Main test.
  //------------------------------------------------------------
  initial begin

    rst_n          = 1'b0;

    key            = 128'd0;
    key_valid      = 1'b0;

    data_in        = 128'd0;
    data_in_valid  = 1'b0;

    expected_mask  = 8'd0;

    fail_count     = 0;
    tap_fail_count = 0;
    wait_count     = 0;


    //----------------------------------------------------------
    // T04 trigger sequence.
    //----------------------------------------------------------
    t04_pt_a5 =
        128'hA500_0000_0000_0000_0000_0000_0000_0001;

    t04_pt_5a =
        128'h5A00_0000_0000_0000_0000_0000_0000_0002;

    t04_pt_ff =
        128'hFF00_0000_0000_0000_0000_0000_0000_0003;


    //----------------------------------------------------------
    // Required detector mask for each benchmark.
    //
    // T01: KLG is mandatory; ORC may also detect corrupted result.
    // T02: design requires KLG + ORC.
    // T03: design requires RCM + ORC.
    // T04: current benchmark requires FIC + RED.
    // T05: RCM is mandatory; RED may also flag rare FF...FF input.
    //----------------------------------------------------------
    if ((`CASE == "T01_p1_key_dump") ||
        (`CASE == "T01"))
      expected_mask =
          (8'h01 << `AEGIS_ST_KLG);

    else if ((`CASE == "T02_p2_slow_leak") ||
             (`CASE == "T02"))
      expected_mask =
          (8'h01 << `AEGIS_ST_KLG) |
          (8'h01 << `AEGIS_ST_ORC);

    else if ((`CASE == "T03_p3_skip_mixcol") ||
             (`CASE == "T03"))
      expected_mask =
          (8'h01 << `AEGIS_ST_RCM) |
          (8'h01 << `AEGIS_ST_ORC);

    else if ((`CASE == "T04_p4_debug_port") ||
             (`CASE == "T04"))
      expected_mask =
          (8'h01 << `AEGIS_ST_FIC) |
          (8'h01 << `AEGIS_ST_RED);

    else if ((`CASE == "T05_dos_trojan") ||
             (`CASE == "T05"))
      expected_mask =
          (8'h01 << `AEGIS_ST_RCM);


    $display("==================================================");
    $display("Security test CASE: %s", `CASE);
    $display("==================================================");


    //----------------------------------------------------------
    // Load clean vector.
    //----------------------------------------------------------
    clean_file =
        $fopen(
          "verif/vectors/fips197_appb.txt",
          "r"
        );

    if (clean_file == 0)
      $fatal(
        1,
        "Khong mo duoc fips197_appb.txt"
      );


    clean_scan_result =
        $fscanf(
          clean_file,
          "%h %h %h\n",
          clean_key,
          clean_pt,
          clean_expected
        );

    $fclose(clean_file);


    if (clean_scan_result != 3)
      $fatal(
        1,
        "Noi dung fips197_appb.txt khong hop le"
      );


    //----------------------------------------------------------
    // Load trigger vector.
    //----------------------------------------------------------
    trigger_file =
        $fopen(
          {"verif/vectors/trigger_", `CASE, ".txt"},
          "r"
        );

    if (trigger_file == 0)
      $fatal(
        1,
        "Khong mo duoc trigger file cho CASE=%s",
        `CASE
      );


    trigger_scan_result =
        $fscanf(
          trigger_file,
          "%h %h %h\n",
          trigger_key,
          trigger_pt,
          trigger_expected
        );

    $fclose(trigger_file);


    if (trigger_scan_result != 3)
      $fatal(
        1,
        "Noi dung trigger file khong hop le"
      );


    if (clean_key !== trigger_key)
      $fatal(
        1,
        "Vector sach va trigger phai dung cung khoa"
      );


    //----------------------------------------------------------
    // Reset.
    //----------------------------------------------------------
    repeat (2) @(negedge clk);

    rst_n = 1'b1;


    //----------------------------------------------------------
    // Key expansion.
    //----------------------------------------------------------
    @(negedge clk);

    key       = clean_key;
    key_valid = 1'b1;


    @(negedge clk);

    key_valid = 1'b0;


    wait(busy == 1'b1);
    wait(busy == 1'b0);

    $display("[INFO] Key expansion hoan tat");

    #1;


    //----------------------------------------------------------
    // Verify all AES-128 round-key taps.
    //----------------------------------------------------------
    for (round_idx = 0;
         round_idx < `AEGIS_NUM_RKEY;
         round_idx = round_idx + 1) begin

      if (dut.round_keys_flat[round_idx*128 +: 128] !==
          dut.u_core.keymem.key_mem[round_idx]) begin

        $display(
          "[FAIL] Mapping round key %0d khong dung",
          round_idx
        );

        tap_fail_count = tap_fail_count + 1;
        fail_count     = fail_count + 1;

      end

    end


    if (tap_fail_count == 0)
      $display(
        "[PASS] Cong tapped anh xa dung ca 11 round key AES-128"
      );


    //==========================================================
    // CLEAN PRE-TEST
    //
    // T04 uses its own three-plaintext sequence, so it skips this
    // pre-test to avoid disturbing its trigger FSM.
    //==========================================================
    if (!((`CASE == "T04_p4_debug_port") ||
          (`CASE == "T04"))) begin


      //--------------------------------------------------------
      // Send clean plaintext.
      //--------------------------------------------------------
      @(negedge clk);

      data_in       = clean_pt;
      data_in_valid = 1'b1;


      @(negedge clk);

      data_in_valid = 1'b0;


      wait(busy == 1'b1);
      wait(dut.core_dvalid == 1'b1);

      #1;


      clean_internal_output =
          dut.core_dout;

      clean_payload_cycle =
          cycle_count;


      //--------------------------------------------------------
      // Functional correctness.
      //--------------------------------------------------------
      if (clean_internal_output === clean_expected)
        $display(
          "[PASS] Core tao dung ciphertext sach: %h",
          clean_internal_output
        );
      else begin

        $display(
          "[FAIL] Ciphertext sach noi bo khong dung"
        );

        $display(
          "       Mong doi: %h",
          clean_expected
        );

        $display(
          "       Thuc te : %h",
          clean_internal_output
        );

        fail_count = fail_count + 1;

      end


      //--------------------------------------------------------
      // Output must be held until KLG verdict.
      //--------------------------------------------------------
      if ((data_out_valid === 1'b0) &&
          (data_out === 128'd0))
        $display(
          "[PASS] Output sach bi giu trong khi cho verdict"
        );
      else begin

        $display(
          "[FAIL] Output sach xuat hien truoc verdict"
        );

        fail_count = fail_count + 1;

      end


      wait(dut.klg_verdict_valid == 1'b1);

      #1;


      clean_output_cycle =
          cycle_count;


      //--------------------------------------------------------
      // No KLG false alarm on the clean FIPS vector.
      //--------------------------------------------------------
      if (dut.klg_alarm === 1'b0)
        $display(
          "[PASS] KLG khong bao dong voi ciphertext sach"
        );
      else begin

        $display(
          "[FAIL] KLG bao dong nham voi ciphertext sach"
        );

        $display(
          "       klg_code=%0d",
          dut.klg_code
        );

        fail_count = fail_count + 1;

      end


      //--------------------------------------------------------
      // One-cycle security verdict latency.
      //--------------------------------------------------------
      if ((clean_output_cycle -
           clean_payload_cycle) == 1)
        $display(
          "[PASS] Ciphertext sach duoc phat sau 1 chu ky"
        );
      else begin

        $display(
          "[FAIL] Latency output sach = %0d, mong doi = 1",
          clean_output_cycle - clean_payload_cycle
        );

        fail_count = fail_count + 1;

      end


      //--------------------------------------------------------
      // Wrapper output.
      //--------------------------------------------------------
      if ((data_out_valid === 1'b1) &&
          (data_out === clean_expected))
        $display(
          "[PASS] Wrapper phat dung ciphertext sach"
        );
      else begin

        $display(
          "[FAIL] Wrapper khong phat dung ciphertext sach"
        );

        fail_count = fail_count + 1;

      end


      //--------------------------------------------------------
      // Wait for output-valid window to close.
      //--------------------------------------------------------
      wait(dut.state == 3'd3);

      repeat (3) @(negedge clk);

      #1;


      if ((data_out_valid === 1'b0) &&
          (data_out === 128'd0))
        $display(
          "[PASS] Valid chi keo dai 1 chu ky, data_out bi reset"
        );
      else begin

        $display(
          "[FAIL] Output sach khong dong lai dung sau 1 chu ky"
        );

        fail_count = fail_count + 1;

      end


      //--------------------------------------------------------
      // Clean-only case.
      //--------------------------------------------------------
      if ((`CASE == "clean") ||
          (`CASE == "CLEAN") ||
          (`CASE == "C")) begin

        if (sec_alarm === 1'b0)
          $display(
            "[PASS] Clean case khong co security alarm"
          );
        else begin

          $display(
            "[FAIL] Clean case co security alarm"
          );

          fail_count = fail_count + 1;

        end


        $display("==================================================");

        if (fail_count == 0) begin

          $display("[PASS] SECURITY TEST HOAN TAT");
          $display("==================================================");

          $finish;

        end
        else begin

          $display(
            "[FAIL] SECURITY TEST CO %0d LOI",
            fail_count
          );

          $display("==================================================");

          $fatal(
            1,
            "SECURITY TEST THAT BAI"
          );

        end

      end

    end


    //==========================================================
    // TROJAN TEST START
    //==========================================================
    if ((`CASE != "clean") &&
        (`CASE != "CLEAN") &&
        (`CASE != "C")) begin

      $display("--------------------------------------------------");
      $display("[INFO] Bat dau Trojan test: %s", `CASE);
      $display("--------------------------------------------------");

    end


    //==========================================================
    // T01 / T02 / T03 / T05
    //==========================================================
    if ((`CASE != "T04_p4_debug_port") &&
        (`CASE != "T04") &&
        (`CASE != "clean") &&
        (`CASE != "CLEAN") &&
        (`CASE != "C")) begin


      //--------------------------------------------------------
      // T02 simulation acceleration.
      //
      // Preserve the real RTL threshold. Only preload the internal
      // counter to threshold-1 in verification.
      //--------------------------------------------------------
      if ((`CASE == "T02_p2_slow_leak") ||
          (`CASE == "T02")) begin

        @(negedge clk);

        dut.u_core.encrypt_counter =
            dut.u_core.T02_TRIGGER_COUNT - 16'd1;

        #1;

        $display(
          "[SETUP] T02 counter preload=%0d threshold=%0d",
          dut.u_core.encrypt_counter,
          dut.u_core.T02_TRIGGER_COUNT
        );

      end


      //--------------------------------------------------------
      // Send trigger plaintext.
      //--------------------------------------------------------
      @(negedge clk);

      data_in       = trigger_pt;
      data_in_valid = 1'b1;


      @(negedge clk);

      data_in_valid = 1'b0;


      //--------------------------------------------------------
      // All non-T04 cases now use the same alarm/result flow.
      //--------------------------------------------------------
      wait_for_security_alarm(1000);

      check_common_security_response();

    end


    //==========================================================
    // T04
    //
    // Specification-aligned T04:
    //   trigger T2 : A5 -> 5A -> FF
    //   payload P4 : unauthorized debug port exposes internal state
    //   detection  : FIC + RED
    //
    // Trigger setup differs, but final result/reporting uses the
    // exact same common flow as T01/T02/T03/T05.
    //==========================================================
    if ((`CASE == "T04_p4_debug_port") ||
        (`CASE == "T04")) begin


      //--------------------------------------------------------
      // Ensure wrapper is ready.
      //--------------------------------------------------------
      if (dut.state != 3'd3)
        wait(dut.state == 3'd3);

      repeat (2) @(posedge clk);


      //--------------------------------------------------------
      // #1 A5...
      //--------------------------------------------------------
      $display(
        "[TRIGGER] T04 plaintext #1: %h",
        t04_pt_a5
      );

      @(negedge clk);

      data_in       = t04_pt_a5;
      data_in_valid = 1'b1;

      @(negedge clk);

      data_in_valid = 1'b0;


      wait(busy == 1'b1);
      wait(busy == 1'b0);

      repeat (2) @(posedge clk);

      #1;


      if (sec_alarm === 1'b1) begin

        $display(
          "[FAIL] T04 hard alarm qua som sau A5"
        );

        fail_count = fail_count + 1;

      end


      if (dut.u_core.t04_seq_state != 2'd1) begin

        $display(
          "[FAIL] T04 trigger FSM khong nhan A5"
        );

        fail_count = fail_count + 1;

      end


      //--------------------------------------------------------
      // #2 5A...
      //--------------------------------------------------------
      $display(
        "[TRIGGER] T04 plaintext #2: %h",
        t04_pt_5a
      );

      @(negedge clk);

      data_in       = t04_pt_5a;
      data_in_valid = 1'b1;

      @(negedge clk);

      data_in_valid = 1'b0;


      wait(busy == 1'b1);


      wait_count = 0;

      while ((busy !== 1'b0) &&
             (sec_alarm !== 1'b1) &&
             (wait_count < 200)) begin

        @(posedge clk);
        wait_count = wait_count + 1;

      end


      if (sec_alarm === 1'b1)
        $fatal(
          1,
          "T04 EARLY ALARM after A5->5A"
        );


      if (busy !== 1'b0)
        $fatal(
          1,
          "T04 PT2 TIMEOUT"
        );


      repeat (2) @(posedge clk);

      #1;


      if (dut.u_core.t04_seq_state != 2'd2) begin

        $display(
          "[FAIL] T04 trigger FSM khong nhan A5->5A"
        );

        fail_count = fail_count + 1;

      end


      //--------------------------------------------------------
      // #3 FF...
      //--------------------------------------------------------
      $display(
        "[TRIGGER] T04 plaintext #3: %h",
        t04_pt_ff
      );

      @(negedge clk);

      data_in       = t04_pt_ff;
      data_in_valid = 1'b1;

      @(negedge clk);

      data_in_valid = 1'b0;


      //--------------------------------------------------------
      // Observe Trojan activation before zeroize resets core.
      //--------------------------------------------------------
      wait_count = 0;

      while ((dut.u_core.trojan_fired !== 1'b1) &&
             (dut.zeroize !== 1'b1) &&
             (wait_count < 10)) begin

        @(posedge clk);
        #1;

        wait_count = wait_count + 1;

      end


      if (dut.u_core.trojan_fired !== 1'b1) begin

        $display(
          "[FAIL] T04 Trojan khong kich hoat"
        );

        fail_count = fail_count + 1;

      end
      else begin

        $display(
          "[PASS] T04 Trojan da kich hoat sau A5->5A->FF"
        );

      end


      //--------------------------------------------------------
      // Verify the actual P4 payload before zeroization.
      //
      // The infected core must open a real debug port and expose
      // internal state/key-schedule material. This distinguishes
      // T04 from the old implementation that only injected an
      // illegal FSM state.
      //--------------------------------------------------------
      if (dut.u_core.debug_valid === 1'b1) begin

        if ((^dut.u_core.debug_data === 1'bx) ||
            (dut.u_core.debug_data === 128'd0)) begin

          $display(
            "[FAIL] T04 debug port mo nhung debug_data khong hop le"
          );

          fail_count = fail_count + 1;

        end
        else begin

          $display(
            "[PASS] T04 P4 debug port da xuat internal state/key material"
          );

          $display(
            "[PAYLOAD] T04 debug_data=%h",
            dut.u_core.debug_data
          );

        end

      end
      else begin

        $display(
          "[FAIL] T04 P4 debug port khong duoc mo"
        );

        fail_count = fail_count + 1;

      end


      //--------------------------------------------------------
      // Common alarm flow.
      //--------------------------------------------------------
      wait_for_security_alarm(100);


      //--------------------------------------------------------
      // T04-specific trigger evidence.
      //--------------------------------------------------------
      if (dut.u_red.red_code !== 8'h10) begin

        $display(
          "[FAIL] T04 RED code=%h, mong doi 10",
          dut.u_red.red_code
        );

        fail_count = fail_count + 1;

      end


      //--------------------------------------------------------
      // Same result format/checks as all other Trojans.
      //--------------------------------------------------------
      check_common_security_response();

    end


    //----------------------------------------------------------
    // Final summary.
    //----------------------------------------------------------
    $display("==================================================");

    if (fail_count == 0) begin

      $display(
        "[PASS] SECURITY TEST HOAN TAT - CASE=%s",
        `CASE
      );

      $display("==================================================");

      $finish;

    end
    else begin

      $display(
        "[FAIL] SECURITY TEST CO %0d LOI - CASE=%s",
        fail_count,
        `CASE
      );

      $display("==================================================");

      $fatal(
        1,
        "SECURITY TEST THAT BAI"
      );

    end

  end


  //------------------------------------------------------------
  // Global watchdog.
  //------------------------------------------------------------
  initial begin

    #500000;

    $display("==================================================");
    $display("[FAIL] SECURITY TEST WATCHDOG TIMEOUT");

    $display(
      "       cycle       = %0d",
      cycle_count
    );

    $display(
      "       wrapper FSM = %0d",
      dut.state
    );

    $display(
      "       core FSM    = %0d",
      dut.u_core.aes_core_ctrl_reg
    );

    $display(
      "       busy        = %b",
      busy
    );

    $display(
      "       sec_alarm   = %b",
      sec_alarm
    );

    $display(
      "       sec_warning = %b",
      sec_warning
    );

    $display(
      "       sec_status  = %b",
      sec_status
    );

    $display(
      "       zeroize     = %b",
      dut.zeroize
    );

    $display(
      "       KLG alarm   = %b",
      dut.u_klg.klg_alarm
    );

    $display(
      "       FIC alarm   = %b",
      dut.u_fic.fic_alarm
    );

    $display(
      "       RCM alarm   = %b",
      dut.u_rcm.rcm_alarm
    );

    $display(
      "       ORC alarm   = %b",
      dut.orc_alarm
    );

    $display(
      "       RED warning = %b",
      dut.u_red.red_warning
    );

    $display(
      "       RED code    = %h",
      dut.u_red.red_code
    );

    $display("==================================================");

    $fatal(
      1,
      "SECURITY TEST TIMEOUT"
    );

  end

endmodule
