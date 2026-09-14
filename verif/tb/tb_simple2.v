`timescale 1ns/1ps
`include "aegis_defs.vh"

module tb_simple2;

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

  aegis_aes_top dut (
    .clk(clk), .rst_n(rst_n), .key(key), .key_valid(key_valid),
    .data_in(data_in), .data_in_valid(data_in_valid),
    .data_out(data_out), .data_out_valid(data_out_valid),
    .busy(busy), .sec_alarm(sec_alarm),
    .sec_warning(), .sec_status()
  );

  initial begin
    clk = 0;
    forever #5 clk = ~clk;
  end

  initial begin
    rst_n = 0;
    key = 0;
    key_valid = 0;
    data_in = 0;
    data_in_valid = 0;

    #100;
    rst_n = 1;
    #50;

    $display("=== Simple Test ===");

    key = 128'h000102030405060708090a0b0c0d0e0f;
    key_valid = 1;
    @(posedge clk);
    key_valid = 0;

    wait(busy == 0);
    $display("Key loaded, waiting one extra cycle...");

    // Wait one extra cycle for FSM to settle
    @(posedge clk);
    #1;

    data_in = 128'h00112233445566778899aabbccddeeff;
    data_in_valid = 1;
    @(posedge clk);
    data_in_valid = 0;

    wait(data_out_valid);
    $display("Result: %h", data_out);
    $display("Expected: 69c4e0d86a7b0430d8cdb78070b4c55a");

    $finish;
  end

  initial begin
    #5000000;
    $display("[TIMEOUT]");
    $finish;
  end

endmodule
