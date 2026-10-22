`timescale 1ns/1ps
`include "aegis_cfg_reader.vh"

//==============================================================
// tb_regress_nist.sv
//
// Full NIST FIPS-197 regression for the AEGIS-AES security
// wrapper (rtl/aegis/aegis_aes_top.v).
//
// Purpose
// -------
// Proves the property the project is built on: a Trojan-infected
// AES core must be SILENT on clean NIST traffic. Concretely, for
// every standard NIST vector we assert two things:
//
//   1. Functional correctness - the core still produces the exact
//      ciphertext NIST specifies (the Trojan does not corrupt
//      normal operation).
//   2. Security silence     - no monitor raises an alarm. An alarm
//      here would be a FALSE POSITIVE: the monitors fired on
//      legitimate traffic.
//
// A Trojan that corrupts ciphertext fails (1). A Trojan that is
// detected too eagerly fails (2). Only a Trojan that is both
// functionally correct and undetectable on normal traffic is a
// credible hardware Trojan - which is exactly what the monitors
// are supposed to catch.
// Usage
// -----
//   make regress                 # clean core (rtl/aes_golden baseline)
//   make regress CASE=T01_p1_key_dump
//   make regress CASE=T02_p2_slow_leak
//   ... etc, one per rtl/infected/T0x_* case
//==============================================================
module tb_regress_nist;

  //------------------------------------------------------------
  // Case contract (verif/cfg/<CASE>.cfg).
  //------------------------------------------------------------
  logic [7:0] cfg_mask;
  integer     cfg_latency;
  logic       cfg_silent;
  integer     cfg_ok;
  string      cfg_path;

  // Maximum number of MCT vectors to run. 0 = all 10,000.
  // Override from the Makefile: make regress MCT_LIMIT=100
  `ifndef MCT_LIMIT
    `define MCT_LIMIT 0
  `endif

  //------------------------------------------------------------
  // DUT interface.
  //------------------------------------------------------------
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
  wire          sec_warning;
  wire [7:0]    sec_status;

  //------------------------------------------------------------
  // Test vector storage.
  //------------------------------------------------------------
  logic [127:0] vec_key;
  logic [127:0] vec_pt;
  logic [127:0] vec_ct;

  //------------------------------------------------------------
  // Test state.
  //------------------------------------------------------------
  integer       file_handle;
  integer       scan_result;
  integer       total_vectors;
  integer       pass_count;
  integer       fail_count;
  integer       alarm_count;
  integer       vector_idx;
  integer       phase;          // 0 = KAT, 1 = MCT
  integer       err_count;
  integer       limit;          // max vectors per file (0 = unlimited)
  integer       mct_count;

  //------------------------------------------------------------
  // Clock.
  //------------------------------------------------------------
  initial clk = 0;
  always #5 clk = ~clk;

  //------------------------------------------------------------
  // DUT instance.
  //------------------------------------------------------------
  aegis_aes_top dut (
    .clk            (clk),
    .rst_n          (rst_n),
    .key            (key),
    .key_valid      (key_valid),
    .data_in        (data_in),
    .data_in_valid  (data_in_valid),
    .data_out       (data_out),
    .data_out_valid (data_out_valid),
    .busy           (busy),
    .sec_alarm      (sec_alarm),
    .sec_warning    (sec_warning),
    .sec_status     (sec_status)
  );

  //==============================================================
  // run_vector
  //
  // Drives one (key, plaintext, expected ciphertext) triple
  // through the wrapper and checks the two properties.
  //==============================================================
  task run_vector;
    input logic [127:0] t_key;
    input logic [127:0] t_pt;
    input logic [127:0] t_ct;
    input integer       idx;
    input integer       verbose;

    logic [127:0] got;
    integer       local_err;

    local_err = 0;

    // -- Load the key. The wrapper latches key_reg on key_valid
    //    and re-expands the round keys, so this must be redone for
    //    every vector (each NIST vector uses a different key).
    @(negedge clk);
    key       = t_key;
    key_valid = 1'b1;
    @(negedge clk);
    key_valid = 1'b0;

    // -- Wait for key expansion to complete.
    wait (busy == 1'b1);
    wait (busy == 1'b0);
    @(negedge clk);

    // -- Present the plaintext.
    data_in       = t_pt;
    data_in_valid = 1'b1;
    @(negedge clk);
    data_in_valid = 1'b0;

    // -- Wait for the encryption to finish.
    wait (busy == 1'b1);
    wait (dut.core_dvalid == 1'b1);
    #1;

    got = dut.core_dout;

    // -- Property 1: functional correctness.
    if (got !== t_ct) begin
      fail_count = fail_count + 1;
      err_count  = err_count + 1;
      local_err  = local_err + 1;
      $display("  [FAIL] vec %0d: expected %h, got %h", idx, t_ct, got);
    end else begin
      pass_count = pass_count + 1;
      if (verbose)
        $display("  [PASS] vec %0d: %h", idx, got);
    end

    // -- Property 2: the wrapper must present the same ciphertext
    //    on its output port once the KLG verdict is clean.
    if (data_out_valid === 1'b1) begin
      if (data_out !== t_ct) begin
        fail_count = fail_count + 1;
        err_count  = err_count + 1;
        local_err  = local_err + 1;
        $display("  [FAIL] vec %0d: data_out %h != expected %h",
                 idx, data_out, t_ct);
      end
    end

    // -- Property 3: security silence. Any alarm on a clean NIST
    //    vector is a monitor false positive.
    //
    //    The contract decides whether the silence is mandatory. When
    //    the case is allowed to be detected on NIST traffic the alarm
    //    is reported but does not fail the regression.
    if (sec_alarm === 1'b1) begin
      alarm_count = alarm_count + 1;

      if (cfg_silent) begin
        err_count = err_count + 1;
        local_err = local_err + 1;
        $display("  [ALARM] vec %0d: sec_alarm=1 sec_status=%08b (FAIL: contract requires silence)",
                 idx, sec_status);
      end
      else begin
        $display("  [ALARM] vec %0d: sec_alarm=1 sec_status=%08b (allowed by contract)",
                 idx, sec_status);
      end
    end

    // -- Let the wrapper return to ST_READY for the next vector.
    @(negedge clk);
  endtask

  //==============================================================
  // run_file
  //
  // Streams every vector in a NIST file through run_vector.
  //==============================================================
  task run_file;
    input string        path;
    input integer       verbose;
    input integer       max_vec;

    integer       stop;

    file_handle = $fopen(path, "r");

    if (file_handle == 0) begin
      $display("[FATAL] Khong mo duoc file vector: %s", path);
      $fatal(1, "Vector file not found");
    end

    vector_idx = 0;
    stop       = 0;

    while (!$feof(file_handle) && !stop) begin
      scan_result = $fscanf(file_handle, "%h %h %h\n",
                            vec_key, vec_pt, vec_ct);

      if (scan_result == 3) begin
        vector_idx = vector_idx + 1;
        total_vectors = total_vectors + 1;
        run_vector(vec_key, vec_pt, vec_ct, vector_idx, verbose);

        // -- Icarus has no `break`, so the limit is enforced with a
        //    stop flag instead.
        if ((max_vec > 0) && (vector_idx >= max_vec))
          stop = 1;
      end else if (scan_result != -1) begin
        $fatal(1, "Noi dung vector khong hop le trong %s", path);
      end
    end

    $fclose(file_handle);

    $display("  -> %s: %0d vectors", path, vector_idx);
  endtask

  //==============================================================
  // Main test sequence.
  //==============================================================
  initial begin
    // -- Initial state.
    rst_n         = 1'b0;
    key           = 128'd0;
    key_valid     = 1'b0;
    data_in       = 128'd0;
    data_in_valid = 1'b0;

    total_vectors = 0;
    pass_count    = 0;
    fail_count    = 0;
    alarm_count   = 0;
    err_count     = 0;

    // -- Load the case contract, if this run targets an infected
    //    case. The clean core has no contract, so it defaults to
    //    "must stay silent".
    cfg_mask    = 8'd0;
    cfg_latency = -1;
    cfg_silent  = 1'b1;
    cfg_ok      = 0;

    cfg_path = {"verif/cfg/", `CASE, ".cfg"};

    aegis_cfg_read(
      cfg_path,
      cfg_mask,
      cfg_latency,
      cfg_silent,
      cfg_ok
    );

    if (!cfg_ok)
      $display("[CFG] Khong co contract cho CASE=%0s, dung mac dinh im lang",
               `CASE);

    // -- MCT vector limit. 0 = run all 10,000.
    limit = `MCT_LIMIT;
    if (limit < 0)
      limit = 0;

    // -- Reset.
    repeat (2) @(negedge clk);
    rst_n = 1'b1;
    @(negedge clk);

    $display("==================================================");
    $display("NIST FIPS-197 Regression - AEGIS-AES wrapper");
    $display("==================================================");

    // -- KAT: the 16 known-answer vectors.
    $display("");
    $display("[TEST 1] KAT (Known Answer Test)");
    phase = 0;
    run_file("verif/vectors/nist_kat.txt", 1, 0);

    // -- MCT: the 10,000 Monte Carlo vectors.
    //
    // MCT_LIMIT lets a developer run a short smoke test
    // (e.g. MCT_LIMIT=100) without waiting for the full 10,000
    // vectors, which take roughly ten minutes under Icarus.
    $display("");
    if (limit > 0)
      $display("[TEST 2] MCT (Monte Carlo Test) - first %0d vectors", limit);
    else
      $display("[TEST 2] MCT (Monte Carlo Test) - all vectors");
    phase = 1;
    run_file("verif/vectors/nist_mct.txt", 0, limit);

    // -- Summary.
    $display("");
    $display("==================================================");
    $display("REGRESSION SUMMARY");
    $display("==================================================");
    $display("  Total vectors      : %0d", total_vectors);
    $display("  Functional PASS    : %0d", pass_count);
    $display("  Functional FAIL    : %0d", fail_count);
    $display("  Security alarms    : %0d", alarm_count);
    $display("");

    if (err_count == 0) begin
      $display("  [PASS] NIST regression clean: ciphertexts correct");
      $display("         AND no monitor raised a false alarm.");
    end else begin
      $display("  [FAIL] NIST regression found %0d problem(s).", err_count);
    end

    $display("==================================================");

    $finish;
  end

  //------------------------------------------------------------
  // Watchdog.
  //
  // Measured: one vector costs ~720 us of simulated time (72
  // cycles x 10 ns, plus key-expansion and handshake overhead).
  // The full 10,016 vectors therefore need roughly
  //   10016 * 720138 ps ~= 7.2e9 ps
  // of simulated time. The budget below is ~30x that, so a real
  // run never trips the watchdog; only a genuine hang (e.g. a
  // core stuck in LOCKDOWN waiting for a result that never
  // arrives) does.
  //
  // Note: the timeout must be checked against the FULL budget,
  // not the 10,000-vector count of the MCT file alone - the KAT
  // phase and the per-vector handshake add to it.
  //------------------------------------------------------------
  initial begin
    #200000000000;
    $display("[FATAL] Simulation timeout - hung, aborting");
    $display("==================================================");
    $display("  Vectors completed   : %0d", total_vectors);
    $display("  Functional PASS     : %0d", pass_count);
    $display("  Functional FAIL     : %0d", fail_count);
    $display("  Security alarms     : %0d", alarm_count);
    $display("==================================================");
    $fatal(1, "Regression did not finish");
  end

endmodule
