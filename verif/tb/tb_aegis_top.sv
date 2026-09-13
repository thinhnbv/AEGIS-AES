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

  integer trigger_file;
  integer trigger_scan_result;

  integer file, scan_result;

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
    $display("1. Dang nap vector tu file fips197_appb.txt...");

    file = $fopen("verif/vectors/fips197_appb.txt", "r");
    if (file == 0) begin
      $display("[LOI] Khong the mo file vector!");
      $fatal(1, "Khong the mo file fips197_appb.txt");
    end
    scan_result = $fscanf(file, "%h %h %h\n", nist_key, nist_pt, nist_ct);
    $fclose(file);

    if (scan_result != 3) begin
      $fatal(1, "Noi dung fips197_appb.txt khong hop le");
    end

    $display("   Da nap Key      : %h", nist_key);
    $display("   Da nap Plaintext: %h", nist_pt);

    // Khoi tao muc thap
    reset_n = 0; encdec = 1; init = 0; next = 0; keylen = 0;
    key = {nist_key, nist_key};
    block = 128'h0;

    // Doi 2 chu ky va nha reset
    @(negedge clk);
    @(negedge clk);
    reset_n = 1;

    // --- BUOC 1: NAP KHOA (KEY EXPANSION) ---
    @(negedge clk);
    init = 1;
    @(negedge clk);
    init = 0;

    wait(ready == 1'b0);
    wait(ready == 1'b1);
    $display("   [+] Mo rong khoa (Key Expansion) hoan tat.");

    // --- BUOC 2: NAP BAN RO VA MA HOA (NIST) ---
    @(negedge clk);
    block = nist_pt;
    next  = 1;
    @(negedge clk);
    next  = 0;

    wait(result_valid == 1'b1);
    @(negedge clk);

    // --- BUOC 3: DOI CHIEU KET QUA NIST ---
    if (result == nist_ct) begin
      $display("==================================================");
      $display("   [PASS] Ciphertext khop hoan toan voi vector da nap!");
      $display("   Output thuc te  : %h", result);
      $display("==================================================");
    end else begin
      $display("==================================================");
      $display("   [FAIL] Ciphertext KHONG khop!");
      $display("   Mong doi : %h", nist_ct);
      $display("   Thuc te  : %h", result);
      $display("==================================================");
      $fatal(1, "NIST REGRESSION THAT BAI");
    end

    // --- BUOC 4: KIEM TRA T03 TROJAN ---
    trigger_file = $fopen("verif/vectors/trigger_T03.txt", "r");

    if (trigger_file == 0) begin
      $display("[FAIL] Khong mo duoc trigger_T03.txt");
      $fatal(1, "Khong mo duoc trigger_T03.txt");
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
      $display("[FAIL] Noi dung trigger_T03.txt khong hop le");
      $fatal(1, "Noi dung trigger_T03.txt khong hop le");
    end

    // Nap lai khoa cho T03
    @(negedge clk);
    key   = {trigger_key, trigger_key};
    block = 128'h0;
    init  = 1;

    @(negedge clk);
    init = 0;

    wait(ready == 1'b0);
    wait(ready == 1'b1);

    // Gui plaintext kich hoat T03 (123456789ABCDEF00000000000000001)
    @(negedge clk);
    block = trigger_pt;
    next  = 1;

    @(negedge clk);
    next = 0;

    // Cho encryption hoan tat
    wait(result_valid == 1'b1);
    @(negedge clk);

    if (result == trigger_expected) begin
      $display("==================================================");
      $display("   [PASS] T03 da duoc kich hoat dung!");
      $display("   Output quan sat : %h", result);
      $display("   Mong doi        : %h", trigger_expected);
      $display("==================================================");
    end else begin
      $display("==================================================");
      $display("   [FAIL] T03 khong cho ket qua mong doi");
      $display("   Mong doi : %h", trigger_expected);
      $display("   Thuc te  : %h", result);
      $display("==================================================");
      $fatal(1, "T03 KHONG DUOC KICH HOAT");
    end

    $finish;
  end
endmodule
