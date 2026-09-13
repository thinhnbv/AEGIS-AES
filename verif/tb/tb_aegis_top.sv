`timescale 1ns/1ps

module tb_aegis_top;
  logic           clk;
  logic           reset_n;
  logic           encdec;
  logic           init;
  logic           next;
  logic           ready;
  logic [255:0]   key;
  logic           keylen;
  logic [127:0]   block;
  logic [127:0]   result;
  logic           result_valid;

  logic [127:0]   nist_key;
  logic [127:0]   nist_pt;
  logic [127:0]   nist_ct;

  logic [127:0]   trigger_key;
  logic [127:0]   trigger_pt;
  logic [127:0]   trigger_expected;

  integer file_kat;
  integer file_trigger;
  integer scan_result;
  integer pass_count;
  integer fail_count;
  integer vec_num;

  initial begin
    clk = 0;
    forever #5 clk = ~clk;
  end

  aes_core dut (
    .clk(clk), .reset_n(reset_n), .encdec(encdec), .init(init),
    .next(next), .ready(ready), .key(key), .keylen(keylen),
    .block(block), .result(result), .result_valid(result_valid)
  );

  initial begin
    pass_count = 0;
    fail_count = 0;
    vec_num = 0;

    $display("==================================================");
    $display("   AES-128 NIST REGRESSION + TROJAN TEST");
    $display("==================================================");

    // --- DOC KAT (16 vector) ---
    $display("");
    $display("=== Doc KAT vectors (nist_kat.txt) ===");
    file_kat = $fopen("verif/vectors/nist_kat.txt", "r");
    if (file_kat == 0) begin
      $display("[LOI] Khong the mo nist_kat.txt!");
      $fatal(1);
    end
    while (!$feof(file_kat)) begin
      scan_result = $fscanf(file_kat, "%h %h %h\n", nist_key, nist_pt, nist_ct);
      if (scan_result == 3) begin
        vec_num = vec_num + 1;

        // Reset
        reset_n = 0; encdec = 1; init = 0; next = 0; keylen = 0;
        key = 256'h0; block = 128'h0;
        @(negedge clk);
        @(negedge clk);
        reset_n = 1;
        @(negedge clk);

        // Load key
        key = {nist_key, nist_key};
        init = 1;
        @(negedge clk);
        init = 0;
        wait(ready == 1'b0);
        wait(ready == 1'b1);

        // Encrypt
        @(negedge clk);
        block = nist_pt;
        next = 1;
        @(negedge clk);
        next = 0;
        wait(result_valid == 1'b1);
        @(negedge clk);

        // Kiem tra
        if (result == nist_ct) begin
          pass_count = pass_count + 1;
        end else begin
          fail_count = fail_count + 1;
          $display("   [FAIL] KAT #%0d", vec_num);
        end
      end
    end
    $fclose(file_kat);
    $display("[+] KAT: %0d pass, %0d fail", pass_count, fail_count);

    if (fail_count > 0) begin
      $fatal(1, "NIST REGRESSION THAT BAI");
    end

    // --- KIEM TRA T01 TROJAN ---
    $display("");
    $display("=== Kiem tra T01 Trojan (trigger_T01.txt) ===");
    file_trigger = $fopen("verif/vectors/trigger_T01.txt", "r");
    if (file_trigger == 0) begin
      $display("[FAIL] Khong mo duoc trigger_T01.txt");
      $fatal(1);
    end
    scan_result = $fscanf(file_trigger, "%h %h %h\n", trigger_key, trigger_pt, trigger_expected);
    $fclose(file_trigger);

    if (scan_result != 3) begin
      $display("[FAIL] Noi dung trigger_T01.txt khong hop le");
      $fatal(1);
    end

    // Nap lai khoa cho phep thu T01
    @(negedge clk);
    key = {trigger_key, trigger_key};
    block = 128'h0;
    init = 1;
    @(negedge clk);
    init = 0;
    wait(ready == 1'b0);
    wait(ready == 1'b1);

    // Gui plaintext kich hoat T01
    @(negedge clk);
    block = trigger_pt;
    next = 1;
    @(negedge clk);
    next = 0;
    wait(result_valid == 1'b0);
    wait(result_valid == 1'b1);
    @(negedge clk);

    if (result == trigger_expected) begin
      $display("   [PASS] T01 da duoc kich hoat dung trong mo phong");
      $display("   Output quan sat : %h", result);
    end else begin
      $display("   [FAIL] T01 khong cho ket qua mong doi");
      $display("   Mong doi : %h", trigger_expected);
      $display("   Thuc te  : %h", result);
      $fatal(1, "T01 KHONG DUOC KICH HOAT");
    end

    $display("==================================================");
    $display("   TONG KET");
    $display("   KAT vectors : %0d pass, %0d fail", pass_count, fail_count);
    $display("   Trojan T01  : PASS");
    $display("==================================================");

    $finish;
  end
endmodule
