`timescale 1ns/1ps

module tb_aes_golden;
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
      $display("[LOI] Khong the mo file vector! Kiem tra lai duong dan.");
      $fatal(1, "Khong the mo file vector fips197_appb.txt");
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
    
    // [TRICK PHAN CUNG] Nap key vao ca 2 nua de tranh nham lan mapping cua secworks
    key = {nist_key, nist_key}; 
    block = 128'h0;

    // Doi 2 chu ky va nha reset (Dong bo theo canh xuong)
    @(negedge clk);
    @(negedge clk);
    reset_n = 1;

    // --- BUOC 1: NAP KHOA (KEY EXPANSION) ---
    @(negedge clk);
    init = 1;
    @(negedge clk);
    init = 0;

    // FIX TIMING: Cho ready xuong 0 (dang tinh toan) roi moi doi no len 1 (tinh xong)
    wait(ready == 1'b0);
    wait(ready == 1'b1);
    $display("   [+] Mo rong khoa (Key Expansion) hoan tat.");

    // --- BUOC 2: NAP BAN RO VA MA HOA ---
    @(negedge clk);
    block = nist_pt;
    next  = 1;
    @(negedge clk);
    next  = 0;

    // Cho den khi co ket qua hop le
    wait(result_valid == 1'b1);
    @(negedge clk);

    // --- BUOC 3: DOI CHIEU KET QUA ---
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
      $fatal(1, "AES GOLDEN TEST THAT BAI");
    end
    $finish;
  end
endmodule
