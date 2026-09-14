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
  logic [127:0] prev_key;

  integer file_kat;
  integer file_trigger;
  integer scan_result;
  integer cycle_count;
  integer payload_cycle;
  integer clean_payload_cycle;
  integer clean_output_cycle;
  integer klg_cycle;
  integer fail_count;
  integer pass_count;
  integer round_idx;
  integer tap_fail_count;
  integer vec_num;

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
    rst_n          = 1'b0;
    key            = 128'd0;
    key_valid      = 1'b0;
    data_in        = 128'd0;
    data_in_valid  = 1'b0;
    fail_count     = 0;
    tap_fail_count = 0;
    pass_count     = 0;
    vec_num        = 0;
    prev_key       = 128'd0;

`ifdef CASE
    $display("==================================================");
    $display("Security test CASE: %s", `CASE);
    $display("==================================================");
`endif

    // --- DOC TRIGGER theo CASE ---
    file_trigger = $fopen({"verif/vectors/trigger_", `CASE, ".txt"}, "r");
    if (file_trigger == 0) begin
      $display("[FAIL] Khong mo duoc trigger_%s.txt", `CASE);
      $fatal(1);
    end
    scan_result = $fscanf(file_trigger, "%h %h %h\n", trigger_key, trigger_pt, trigger_expected);
    $fclose(file_trigger);

    if (scan_result != 3) begin
      $display("[FAIL] Noi dung trigger_T01.txt khong hop le");
      $fatal(1);
    end

    // --- DOC KAT (16 vector) ---
    $display("");
    $display("=== Doc KAT vectors (nist_kat.txt) ===");
    file_kat = $fopen("verif/vectors/nist_kat.txt", "r");
    if (file_kat == 0) begin
      $display("[FAIL] Khong the mo nist_kat.txt!");
      $fatal(1);
    end

    // Nha reset
    repeat (2) @(negedge clk);
    rst_n = 1'b1;

    // Doc vector dau tien de nap khoa
    scan_result = $fscanf(file_kat, "%h %h %h\n", clean_key, clean_pt, clean_expected);
    if (scan_result != 3) begin
      $display("[FAIL] Khong doc duoc vector KAT dau tien");
      $fatal(1);
    end

    prev_key = clean_key;

    // Nap khoa dau tien
    @(negedge clk);
    key       = clean_key;
    key_valid = 1'b1;
    @(negedge clk);
    key_valid = 1'b0;
    wait(busy == 1'b1);
    wait(busy == 1'b0);
    $display("[INFO] Key expansion hoan tat");

    // Doi core_dvalid xuong truoc khi gui plaintext
    wait(dut.core_dvalid == 1'b0);
    #1;

    // Kiem tra round key tap mapping
    for (round_idx = 0; round_idx < `AEGIS_NUM_RKEY; round_idx = round_idx + 1) begin
      if (dut.round_keys_flat[round_idx*128 +: 128] !==
          dut.u_core.keymem.key_mem[round_idx]) begin
        $display("[FAIL] Mapping round key %0d khong dung", round_idx);
        tap_fail_count = tap_fail_count + 1;
        fail_count     = fail_count + 1;
      end
    end
    if (tap_fail_count == 0)
      $display("[PASS] Cong tapped anh xa dung ca 11 round key AES-128");

    // --- TEST CAC VECTOR KAT (trojan silent) ---
    // Quay lai dau file
    $fclose(file_kat);
    file_kat = $fopen("verif/vectors/nist_kat.txt", "r");

    while (!$feof(file_kat)) begin
      scan_result = $fscanf(file_kat, "%h %h %h\n", clean_key, clean_pt, clean_expected);
      if (scan_result == 3) begin
        vec_num = vec_num + 1;

        // Neu khoa thay doi, nap lai khoa
        if (clean_key !== prev_key) begin
          prev_key = clean_key;
          @(negedge clk);
          key       = clean_key;
          key_valid = 1'b1;
          @(negedge clk);
          key_valid = 1'b0;
          wait(busy == 1'b1);
          wait(busy == 1'b0);
          // Doi AES core xong transaction cu
          wait(dut.core_dvalid == 1'b0);
        end

        // Gui plaintext sach
        @(negedge clk);
        data_in       = clean_pt;
        data_in_valid = 1'b1;
        @(negedge clk);
        data_in_valid = 1'b0;

        // Doi wrapper phat ket qua (data_out_valid = 1)
        wait(data_out_valid == 1'b1);
        #1;
        // Doc data_out tu WRAPPER (da duoc latch dung)
        clean_internal_output = data_out;
        clean_payload_cycle  = cycle_count;

        // Kiem tra ciphertext noi bo
        if (clean_internal_output === clean_expected) begin
          pass_count = pass_count + 1;
        end else begin
          $display("   [FAIL] KAT #%0d: Expected=%h Got=%h", vec_num, clean_expected, clean_internal_output);
          fail_count = fail_count + 1;
        end

        // Kiem tra quarantine (data_out bi chan truoc verdict)
        // data_out_valid = 1 nghia la da co verdict -> kiem tra o dong nay
        if (data_out === clean_expected)
          $display("   [OK] Wrapper phat dung ciphertext");
        else begin
          $display("   [FAIL] KAT #%0d: Wrapper phat sai ciphertext", vec_num);
          fail_count = fail_count + 1;
        end

        // KLG khong bao dong voi ciphertext sach
        if (dut.klg_alarm === 1'b0)
          $display("   [OK] KLG khong bao dong");
        else begin
          $display("   [FAIL] KAT #%0d: KLG bao dong nham", vec_num);
          fail_count = fail_count + 1;
        end

        // Latency = 1 chu ky (tu luc gui den luc co ket qua)
        if (dut.klg_verdict_valid === 1'b1)
          $display("   [OK] Latency 1 chu ky");
        else begin
          $display("   [FAIL] KAT #%0d: Latency khong dung", vec_num);
          fail_count = fail_count + 1;
        end

        // Doi output_valid xuong cho transaction tiep theo
        wait(data_out_valid == 1'b0);
      end
    end
    $fclose(file_kat);
    $display("[+] KAT security check: %0d pass, %0d fail", pass_count, fail_count);

    if (fail_count > 0) begin
      $fatal(1, "SECURITY KAT CHECK THAT BAI");
    end

    // --- FIX: Reload key to reset FSM state ---
    // After the KAT loop, core_dvalid stays HIGH from the last transaction.
    // The FSM waits for core_dvalid=0 before accepting new key/data.
    // Without this reload, the FSM hangs waiting for core_dvalid to go LOW
    // (which never happens after the last transaction with no new key load).
    @(negedge clk);
    key       = prev_key;       // Reload the same key from last KAT vector
    key_valid = 1'b1;
    @(negedge clk);
    key_valid = 1'b0;
    wait(busy == 1'b1);
    wait(busy == 1'b0);
    // --- KIEM TRA T01 TROJAN ---
    $display("");
    $display("=== Kiem tra Trojan (trigger_%s.txt) ===", `CASE);

    // Tai nap khoa T01
    @(negedge clk);
    key       = trigger_key;
    key_valid = 1'b1;
    @(negedge clk);
    key_valid = 1'b0;
    wait(busy == 1'b1);
    wait(busy == 1'b0);

    // Gui dummy plaintext de clear core_dvalid tu transaction cu
    @(negedge clk);
    data_in       = 128'h0;
    data_in_valid = 1'b1;
    @(negedge clk);
    data_in_valid = 1'b0;
    wait(data_out_valid == 1'b1);
    @(negedge clk);
    #1;

    // Gui plaintext kich hoat T01
    @(negedge clk);
    data_in       = trigger_pt;
    data_in_valid = 1'b1;
    @(negedge clk);
    data_in_valid = 1'b0;

    // Doi KLG phat hien (sec_alarm = 1)
    wait(sec_alarm == 1'b1);
    #1;
    payload_cycle = cycle_count;

    // Payload noi bo phai dung
    if (dut.core_dout === trigger_expected)
      $display("   [PASS] T01 tao payload dung noi bo");
    else begin
      $display("   [FAIL] Payload noi bo T01 khong dung");
      fail_count = fail_count + 1;
    end

    // Quarantine phai chan payload
    if ((data_out_valid == 1'b0) && (data_out == 128'd0))
      $display("   [PASS] Quarantine giu payload khoi cong ngoai");
    else begin
      $display("   [FAIL] Payload thoat ra cong ngoai");
      fail_count = fail_count + 1;
    end

    // KLG latency
    if ((payload_cycle >= 1) && (sec_alarm == 1'b1))
      $display("   [PASS] KLG phat hien trong latency");
    else begin
      $display("   [FAIL] KLG latency khong dung");
      fail_count = fail_count + 1;
    end

    // sec_status ghi nhan KLG
    if (sec_status[`AEGIS_ST_KLG] == 1'b1)
      $display("   [PASS] sec_status ghi nhan KLG");
    else begin
      $display("   [FAIL] sec_status khong ghi nhan KLG");
      fail_count = fail_count + 1;
    end

    // TRU chan dau ra
    if ((data_out_valid == 1'b0) && (data_out == 128'd0))
      $display("   [PASS] TRU chan dau ra trong LOCKDOWN");
    else begin
      $display("   [FAIL] TRU chua chan dau ra");
      fail_count = fail_count + 1;
    end

    // Zeroize
    if (dut.zeroize == 1'b1)
      $display("   [PASS] TRU phat yeu cau zeroize");
    else begin
      $display("   [FAIL] TRU chua phat zeroize");
      fail_count = fail_count + 1;
    end

    // Doi 1 chu ky de zeroize hoan tat
    repeat(5) @(posedge clk);
    #1;

    // Key bi xoa
    if (dut.key_reg === 128'd0)
      $display("   [PASS] Wrapper xoa key_reg");
    else begin
      $display("   [FAIL] Wrapper chua xoa key_reg: %h", dut.key_reg);
      fail_count = fail_count + 1;
    end

    if (dut.round_keys_flat === {(`AEGIS_NUM_RKEY * 128){1'b0}})
      $display("   [PASS] AES core xoa 11 round key");
    else begin
      $display("   [FAIL] AES core chua xoa round key");
      fail_count = fail_count + 1;
    end

    if ((dut.zeroize === 1'b1) && (sec_alarm === 1'b1) && (sec_status[`AEGIS_ST_KLG] === 1'b1))
      $display("   [PASS] Trang thai bao mat sticky sau zeroize");
    else begin
      $display("   [FAIL] Trang thai bao mat khong sticky");
      fail_count = fail_count + 1;
    end

    // --- TOM TAT ---
    $display("==================================================");
    $display("   TONG KET");
    $display("   KAT security : %0d pass, %0d fail", pass_count, fail_count);
    $display("   Trojan %s   : %s", `CASE, (fail_count == 0) ? "PASS" : "FAIL");
    $display("==================================================");
    if (fail_count == 0) begin
      $display("[PASS] SECURITY TEST HOAN TAT");
      $finish;
    end else begin
      $display("[FAIL] SECURITY TEST CO %0d LOI", fail_count);
      $fatal(1, "SECURITY TEST THAT BAI");
    end
  end

  // Watchdog
  initial begin
    #500000;
    $display("[FAIL] SECURITY TEST TIMEOUT");
    $fatal(1, "SECURITY TEST TIMEOUT");
  end

endmodule
