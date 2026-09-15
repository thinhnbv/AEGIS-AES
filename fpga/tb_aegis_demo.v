//---------------------------------------------------------------
// tb_aegis_demo.v
// Simple testbench for AEGIS-AES core
//---------------------------------------------------------------
`timescale 1ns/1ps

`default_nettype none

module tb_aegis_demo;

    reg clk;
    reg rst_n;

    // AES signals
    reg            init;
    reg            next;
    reg            encdec;
    reg  [255:0]  key;
    reg            keylen;
    reg  [127:0]  block;
    wire [127:0]  result;
    wire          result_valid;
    wire          ready;
    wire [3:0]    muxed_round_nr;
    wire [127:0]  state_before_final;

    // Instantiate AES
    aes_core_tapped u_aes (
        .clk(clk), .reset_n(rst_n),
        .encdec(encdec), .init(init), .next(next), .ready(ready),
        .key(key), .keylen(keylen), .block(block),
        .result(result), .result_valid(result_valid),
        .round_keys_flat(), .muxed_round_nr(muxed_round_nr),
        .state_before_final(state_before_final)
    );

    // Clock
    initial begin
        clk = 0;
        forever #10 clk = ~clk;
    end

    // Timeout
    initial begin
        #50_000_000_000;
        $display("TIMEOUT!");
        $finish;
    end

    // FIPS-197 Test Vector
    reg [127:0] test_key = 128'h2b7e151628aed2a6abf7158809cf4f3c;
    reg [127:0] test_pt  = 128'h3243f6a8885a308d313198a2e0370734;
    reg [127:0] test_ct  = 128'h3925841d02dc09fbdc118597196a0b32;

    integer errors;
    reg [127:0] result_reg;

    initial begin
        $dumpfile("tb_aegis_demo.vcd");
        $dumpvars(0, tb_aegis_demo);

        errors = 0;
        rst_n = 0;
        init = 0;
        next = 0;
        encdec = 0;
        key = 0;
        keylen = 0;
        block = 0;

        #100;
        rst_n = 1;
        #100;

        $display("=== AES-128 Encryption Test (FIPS-197 Vector 1) ===");
        $display("Key:    %h", test_key);
        $display("Plain:  %h", test_pt);
        $display("Expect: %h", test_ct);

        // Load key
        key = {128'h0, test_key};  // Lower 128 bits for AES-128
        keylen = 0;  // 128-bit
        init = 1;
        #20;
        init = 0;

        // Wait for ready
        wait(ready);
        $display("Key loaded, ready=%b", ready);

        // Set block and start
        block = test_pt;
        encdec = 1;  // Encrypt
        next = 1;
        #20;
        next = 0;

        // Wait for result
        wait(result_valid);
        result_reg = result;

        $display("Result: %h", result_reg);
        $display("Round:  %0d", muxed_round_nr);

        if (result_reg == test_ct) begin
            $display("PASS: Encryption successful!");
        end else begin
            $display("FAIL: Expected %h", test_ct);
            errors = errors + 1;
        end

        #1000;

        $display("");
        $display("=== AES-128 Decryption Test ===");
        $display("Key:    %h", test_key);
        $display("Cipher: %h", test_ct);
        $display("Expect: %h", test_pt);

        // Load key again
        key = {128'h0, test_key};
        init = 1;
        #20;
        init = 0;

        wait(ready);

        // Decrypt
        block = test_ct;
        encdec = 0;  // Decrypt
        next = 1;
        #20;
        next = 0;

        wait(result_valid);
        result_reg = result;

        $display("Result: %h", result_reg);
        $display("Round:  %0d", muxed_round_nr);

        if (result_reg == test_pt) begin
            $display("PASS: Decryption successful!");
        end else begin
            $display("FAIL: Expected %h", test_pt);
            errors = errors + 1;
        end

        #1000;
        $display("");
        if (errors == 0)
            $display("=== ALL TESTS PASSED ===");
        else
            $display("=== %0d TEST(S) FAILED ===", errors);

        $finish;
    end

endmodule
