// Testbench for raw_aes_adapter with T01-infected aes_core_tapped
`timescale 1ns/1ps
`default_nettype none

module tb_raw_aes_adapter;

  reg clk = 0;
  reg rst_n = 0;
  reg key_valid = 0;
  reg data_in_valid = 0;
  reg [127:0] key = 0;
  reg [127:0] data_in = 0;
  wire [127:0] data_out;
  wire data_out_valid;
  wire busy;

  // Clock generation
  always #10 clk = ~clk;

  // Instantiate raw_aes_adapter with aes_core_tapped
  raw_aes_adapter u_dut (
    .clk(clk),
    .rst_n(rst_n),
    .key(key),
    .key_valid(key_valid),
    .data_in(data_in),
    .data_in_valid(data_in_valid),
    .data_out(data_out),
    .data_out_valid(data_out_valid),
    .busy(busy)
  );

  // Test sequence
  initial begin
    $dumpfile("tb_raw_aes_adapter.vcd");
    $dumpvars(0, tb_raw_aes_adapter);

    $display("[INFO] Starting raw_aes_adapter testbench");

    // Wait for reset
    #100;
    rst_n = 1;
    $display("[INFO] Reset deasserted");
    #100;

    // Load key (FIPS-197 test key)
    key = 128'h2b7e151628aed2a6abf7158809cf4f3c;
    key_valid = 1;
    #20;
    key_valid = 0;
    $display("[INFO] Key loaded");

    // Wait for key expansion (~200 cycles)
    wait (busy == 0);
    #100;

    // Encrypt plaintext (FIPS-197 test plaintext)
    data_in = 128'h3243f6a8885a308d313198a2e0370734;
    data_in_valid = 1;
    #20;
    data_in_valid = 0;
    $display("[INFO] Plaintext sent");

    // Wait for result
    wait (data_out_valid == 1);
    #20;

    // Check result
    $display("[RESULT] data_out = %h", data_out);
    if (data_out == 128'h3925841d02dc09fbdc118597196a0b32) begin
      $display("[PASS] Clean encryption matches FIPS-197 ciphertext");
    end else begin
      $display("[FAIL] Expected: 3925841d02dc09fbdc118597196a0b32");
    end

    // Test T01 trigger
    #200;
    data_in = 128'hDEADBEEFCAFEBABE0000000000000000;
    data_in_valid = 1;
    #20;
    data_in_valid = 0;
    $display("[INFO] T01 trigger plaintext sent");

    wait (data_out_valid == 1);
    #20;
    $display("[RESULT] T01 output = %h", data_out);

    if (data_out == 128'h2b7e151628aed2a6abf7158809cf4f3c) begin
      $display("[PASS] T01 leaked the key correctly");
    end else begin
      $display("[FAIL] Expected: 2b7e151628aed2a6abf7158809cf4f3c");
    end

    $display("[INFO] Testbench complete");
    #1000;
    $finish;
  end

  // Timeout watchdog
  initial begin
    #5000000;
    $display("[FAIL] Timeout - test did not complete");
    $finish;
  end

endmodule
