// tb_tapped.v - Simple testbench for aes_core_tapped
`timescale 1ns/1ps
`default_nettype none

module tb_tapped;

reg clk = 0;
reg reset_n = 1;
reg init = 0;
reg next = 0;
reg encdec = 0;
reg [255:0] key = 0;
reg keylen = 0;
reg [127:0] block = 0;
wire [127:0] result;
wire result_valid;
wire ready;
wire [3:0] round_nr;
wire [127:0] state_before_final;
wire [1407:0] round_keys;

always #5 clk = ~clk;

aes_core_tapped dut (
    .clk(clk), .reset_n(reset_n),
    .init(init), .next(next),
    .encdec(encdec), .key(key), .keylen(keylen),
    .block(block), .result(result), .result_valid(result_valid),
    .ready(ready), .muxed_round_nr(round_nr),
    .state_before_final(state_before_final),
    .round_keys_flat(round_keys)
);

reg [127:0] expected_ct = 128'h3925841d02dc09fbdc118597196a0b32;
reg [127:0] expected_pt = 128'h3243f6a8885a308d313198a2e0370734;
integer errors = 0;

initial begin
    $dumpfile("tb_tapped.vcd");
    $dumpvars(0, tb_tapped);
end

initial begin
    // Reset
    #10 reset_n = 0;
    #20 reset_n = 1;
    #10;

    $display("=== AES-128 Encryption Test ===");
    $display("Key:    2b7e151628aed2a6abf7158809cf4f3c");
    $display("Plain:  3243f6a8885a308d313198a2e0370734");
    $display("Expect: 3925841d02dc09fbdc118597196a0b32");

    // Key: upper 128 bits = AES-128 key, lower 128 bits = zeros
    // Format: {actual_key, 128'h0} - matching golden testbench format
    key = {128'h2b7e151628aed2a6abf7158809cf4f3c, 128'h0};
    block = 128'h3243f6a8885a308d313198a2e0370734;

    // Init key - hold init for 2 clock cycles
    init = 1;
    #20;
    init = 0;

    // Wait for key expansion (10 rounds * ~4 cycles/round = ~40 cycles)
    #2000;
    $display("Key ready");

    // Encrypt
    encdec = 1;
    next = 1;
    #20;
    next = 0;

    // Wait for encryption (10 rounds)
    #10000;

    $display("Result: %h", result);
    $display("Round:  %0d", round_nr);

    if (result == expected_ct) begin
        $display("PASS: Encryption");
    end else begin
        $display("FAIL: Expected %h", expected_ct);
        errors = errors + 1;
    end

    #100;

    $display("");
    $display("=== AES-128 Decryption Test ===");

    // Init key again
    init = 1;
    #20;
    init = 0;
    #2000;
    $display("Key ready");

    // Decrypt
    block = expected_ct;
    encdec = 0;
    next = 1;
    #20;
    next = 0;

    #10000;

    $display("Result: %h", result);
    $display("Round:  %0d", round_nr);

    if (result == expected_pt) begin
        $display("PASS: Decryption");
    end else begin
        $display("FAIL: Expected %h", expected_pt);
        errors = errors + 1;
    end

    #100;
    if (errors == 0)
        $display("=== ALL TESTS PASSED ===");
    else
        $display("=== %d TEST(S) FAILED ===", errors);

    $finish;
end

endmodule
