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

  integer file_kat, file_mct;
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
    $display("   AES-128 GOLDEN REGRESSION");
    $display("   KAT (16 vectors) + MCT (10000 vectors)");
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

    // --- DOC MCT (10000 vector) ---
    $display("");
    $display("=== Doc MCT vectors (nist_mct.txt) ===");
    file_mct = $fopen("verif/vectors/nist_mct.txt", "r");
    if (file_mct == 0) begin
      $display("[LOI] Khong the mo nist_mct.txt!");
      $fatal(1);
    end
    while (!$feof(file_mct)) begin
      scan_result = $fscanf(file_mct, "%h %h %h\n", nist_key, nist_pt, nist_ct);
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
          if (fail_count <= 3) begin
            $display("   [FAIL] MCT #%0d", vec_num);
          end
        end
      end
    end
    $fclose(file_mct);
    $display("[+] MCT: %0d pass, %0d fail", pass_count - 16, fail_count);

    // --- TOM TAT ---
    $display("");
    $display("==================================================");
    $display("   TONG KET");
    $display("   Tong  : %0d vector", pass_count + fail_count);
    $display("   Pass  : %0d", pass_count);
    $display("   Fail  : %0d", fail_count);
    $display("==================================================");
    if (fail_count > 0)
      $fatal(1, "CO %0d VECTOR THAT BAI", fail_count);
    else
      $display("   [PASS] Tat ca %0d vector deu khop!", pass_count);

    $finish;
  end
endmodule
