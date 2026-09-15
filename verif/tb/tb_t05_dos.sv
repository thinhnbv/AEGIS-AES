`timescale 1ns/1ps

module tb_t05_dos;

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

  integer file_kat;
  integer scan_result;
  integer pass_count;
  integer fail_count;
  integer vec_num;
  integer timeout_count;

  // Timeout watchdog
  logic watchdog_expired;

  initial begin
    clk = 0;
    forever #5 clk = ~clk;
  end

  // Watchdog counter
  always @(posedge clk or negedge reset_n) begin
    if (!reset_n)
      timeout_count <= 0;
    else if (ready == 1'b0 && next == 1'b0)  // đang encrypt
      timeout_count <= timeout_count + 1;
    else
      timeout_count <= 0;
  end

  assign watchdog_expired = (timeout_count > 1000);  // ~10us timeout

  aes_core dut (
    .clk(clk), .reset_n(reset_n), .encdec(encdec), .init(init),
    .next(next), .ready(ready), .key(key), .keylen(keylen),
    .block(block), .result(result), .result_valid(result_valid)
  );

  initial begin
    pass_count = 0;
    fail_count = 0;
    vec_num = 0;
    timeout_count = 0;

    $display("==================================================");
    $display("   T05 DoS TROJAN TEST");
    $display("==================================================");

    // --- DOC NIST VECTOR (1 vector) ---
    $display("");
    $display("=== Doc NIST vector (fips197_appb.txt) ===");
    file_kat = $fopen("verif/vectors/fips197_appb.txt", "r");
    if (file_kat == 0) begin
      $display("[LOI] Khong the mo fips197_appb.txt!");
      $fatal(1);
    end
    scan_result = $fscanf(file_kat, "%h %h %h\n", nist_key, nist_pt, nist_ct);
    $fclose(file_kat);

    if (scan_result != 3) begin
      $fatal(1, "Noi dung fips197_appb.txt khong hop le");
    end

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
    $display("   [+] Key expansion hoan tat.");

    // Encrypt NIST vector (should work normally)
    @(negedge clk);
    block = nist_pt;
    next = 1;
    @(negedge clk);
    next = 0;
    wait(result_valid == 1'b1);
    @(negedge clk);

    if (result == nist_ct) begin
      $display("   [PASS] NIST vector khop!");
      pass_count = pass_count + 1;
    end else begin
      $display("   [FAIL] NIST vector khong khop!");
      $display("   Mong doi : %h", nist_ct);
      $display("   Thuc te  : %h", result);
      fail_count = fail_count + 1;
    end

    // --- KIEM TRA T05 DOS TROJAN ---
    $display("");
    $display("=== Kiem tra T05 DoS Trojan ===");

    // Reload key
    @(negedge clk);
    key = {nist_key, nist_key};
    init = 1;
    @(negedge clk);
    init = 0;
    wait(ready == 1'b0);
    wait(ready == 1'b1);
    $display("   [*] Key reloaded, ready for DoS test.");

    // Send DoS trigger plaintext
    trigger_key = nist_key;
    trigger_pt = 128'hDEAD_BEEF_CAFE_DOOD_0000_0000_0000_0005;

    @(negedge clk);
    block = trigger_pt;
    next = 1;
    @(negedge clk);
    next = 0;

    // Watchdog: do NOT wait for result_valid==1
    // DoS Trojan sẽ treo core, result_valid sẽ không bao giờ lên 1
    timeout_count = 0;

    // Cho một thời gian đủ để AES hoàn thành bình thường (~10 cycles)
    repeat(500) @(posedge clk);

    // Kiem tra xem core co bi treo khong (ready=0 sau khi qua thời gian)
    if (ready == 1'b0) begin
      $display("==================================================");
      $display("   [PASS] T05 DoS da duoc kich hoat!");
      $display("   Core bi treo: ready=0 sau thoi gian cho phep");
      $display("   (Trojan hoat dong dung)");
      $display("==================================================");
      pass_count = pass_count + 1;
    end else begin
      $display("==================================================");
      $display("   [FAIL] T05 DoS khong hoat dong!");
      $display("   Core van tra loi: ready=%b", ready);
      $display("==================================================");
      fail_count = fail_count + 1;
    end

    // Tong ket
    $display("");
    $display("==================================================");
    $display("   TONG KET");
    $display("   Test: %0d pass, %0d fail", pass_count, fail_count);
    $display("==================================================");

    if (fail_count > 0) begin
      $fatal(1, "T05 DoS TEST THAT BAI");
    end

    $finish;
  end
endmodule
