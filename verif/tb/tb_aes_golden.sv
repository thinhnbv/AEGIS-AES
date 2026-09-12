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

  integer file;
  integer scan_result;
  integer pass_count;
  integer fail_count;

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

    $display("=== AES-128 Golden Regression (KAT + MCT) ===");
    $display("1. Dang doc vector tu nist_vectors.txt...");

    file = $fopen("verif/vectors/nist_vectors.txt", "r");
    if (file == 0) begin
      $display("[LOI] Khong the mo file nist_vectors.txt!");
      $fatal(1, "File khong ton tai");
    end

    // Khoi tao muc thap
    reset_n = 0; encdec = 1; init = 0; next = 0; keylen = 0;
    key = 256'h0;
    block = 128'h0;

    // Doi 2 chu ky roi nha reset
    @(negedge clk);
    @(negedge clk);
    reset_n = 1;

    // Doc va test tung vector den EOF
    while (!$feof(file)) begin
      scan_result = $fscanf(file, "%h %h %h\n", nist_key, nist_pt, nist_ct);

      if (scan_result != 3) begin
        if (!$feof(file)) begin
          $display("[WARN] Dong khong hop le, bo qua.");
        end
      end else begin

      // --- NAP KHOA (KEY EXPANSION) ---
      @(negedge clk);
      key = {nist_key, nist_key};
      init = 1;
      @(negedge clk);
      init = 0;

      wait(ready == 1'b0);
      wait(ready == 1'b1);

      // --- MA HOA ---
      @(negedge clk);
      block = nist_pt;
      next  = 1;
      @(negedge clk);
      next  = 0;

      wait(result_valid == 1'b1);
      @(negedge clk);

      // --- DOI CHIEU KET QUA ---
      if (result == nist_ct) begin
        pass_count = pass_count + 1;
      end else begin
        fail_count = fail_count + 1;
        $display("   [FAIL] Vector #%0d", pass_count + fail_count);
        $display("   Key     : %h", nist_key);
        $display("   PT      : %h", nist_pt);
        $display("   Mong doi: %h", nist_ct);
        $display("   Thuc te : %h", result);
      end
      end
    end

    $fclose(file);

    // --- TOM TAT ---
    $display("==================================================");
    $display("   TONG KET");
    $display("   Pass: %0d", pass_count);
    $display("   Fail: %0d", fail_count);
    $display("==================================================");

    if (fail_count > 0) begin
      $fatal(1, "CO %0d VECTOR THAT BAI", fail_count);
    end else begin
      $display("   [PASS] Tat ca %0d vector deu khop!", pass_count);
    end

    $finish;
  end
endmodule
