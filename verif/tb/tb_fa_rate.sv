`timescale 1ns/1ps

//==============================================================
// tb_fa_rate.sv
//
// False-alarm-rate measurement for the AEGIS-AES security monitors.
//
// Purpose
// -------
// The competition proposal (muc 9.2) requires the report to state
// the number of FALSE ALARMS raised over 1e6 valid encryptions, and
// the FPGA demo (muc 7.2, step 2) requires 1000 random plaintexts
// to produce no warning at all.
//
// tb_regress_nist.sv cannot measure this. It loads a DIFFERENT key
// for every NIST vector, and the KLG sliding-window byte-leak
// detector resets its window on every key change. Each vector
// therefore contributes at most one observation and the window can
// never fill up.
//
// The realistic threat model is different: a key is installed once
// and then used for many encryptions. That is the traffic pattern
// this testbench reproduces.
//
// Method
// ------
// For every key:
//   1. load the key
//   2. encrypt VECTORS_PER_KEY random plaintexts with it
//   3. count how many encryptions raise a monitor alarm
//
// The reported figure is
//
//   false alarms per 1e6 encryptions
//     = (alarms / total encryptions) * 1e6
//
// A monitor that alarms on the very first vector of a key is a
// false positive: the ciphertext is the genuine AES output, so
// nothing is actually leaking.
//
// Usage
// -----
//   make fa-rate
//   make fa-rate CASE=T02_p2_slow_leak
//==============================================================
module tb_fa_rate;

  //------------------------------------------------------------
  // Configuration.
  //------------------------------------------------------------

  // Number of keys to cycle through.
  `ifndef FA_KEYS
    `define FA_KEYS 100
  `endif

  // Number of encryptions per key.
  `ifndef FA_PER_KEY
    `define FA_PER_KEY 1000
  `endif

  // Seed for the plaintext PRNG.
  `ifndef FA_SEED
    `define FA_SEED 32'h1234_5678
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
  // Test state.
  //------------------------------------------------------------
  integer       enc_count;
  integer       alarm_count;
  integer       warning_count;
  integer       key_idx;
  integer       enc_idx;
  integer       total_enc;

  // Previous value of the sticky sec_warning flag, so that warning
  // EVENTS are counted instead of the same event over and over.
  logic         prev_sec_warning;

  logic [127:0] cur_key;

  // $random() needs a variable seed, not an expression.
  integer       seed_a;
  integer       seed_b;

  //------------------------------------------------------------
  // Clock and reset.
  //------------------------------------------------------------
  initial clk = 0;
  always #5 clk = ~clk;

  initial begin
    rst_n          = 1'b0;
    key            = 128'd0;
    key_valid      = 1'b0;
    data_in        = 128'd0;
    data_in_valid  = 1'b0;

    enc_count      = 0;
    alarm_count    = 0;
    warning_count  = 0;
    key_idx        = 0;
    enc_idx        = 0;
    total_enc      = 0;
    prev_sec_warning = 1'b0;

    repeat (4) @(posedge clk);
    rst_n = 1'b1;
    @(posedge clk);

    for (key_idx = 0; key_idx < `FA_KEYS; key_idx = key_idx + 1) begin

      //--------------------------------------------------------
      // Deterministic per-key secret. Varying the key is what
      // makes the byte-level match probability meaningful: the
      // ciphertext byte is effectively random relative to the key
      // byte.
      //--------------------------------------------------------
      seed_a = `FA_SEED + key_idx;
      seed_b = `FA_SEED + key_idx;

      cur_key = {$random(seed_a), $random(seed_b)};

      @(negedge clk);
      key       = cur_key;
      key_valid = 1'b1;
      @(negedge clk);
      key_valid = 1'b0;

      // Wait for the key expansion to complete.
      wait (busy == 1'b1);
      wait (busy == 1'b0);
      @(negedge clk);

      for (enc_idx = 0; enc_idx < `FA_PER_KEY; enc_idx = enc_idx + 1) begin

        //------------------------------------------------------
        // A fresh random plaintext for every encryption.
        //------------------------------------------------------
        seed_a = `FA_SEED + key_idx * 1000 + enc_idx;
        seed_b = `FA_SEED + key_idx * 1000 + enc_idx;

        data_in       = {$random(seed_a), $random(seed_b)};
        data_in_valid = 1'b1;
        @(negedge clk);
        data_in_valid = 1'b0;

        wait (busy == 1'b1);
        wait (busy == 1'b0);
        @(negedge clk);

        enc_count = enc_count + 1;

        //------------------------------------------------------
        // An alarm here is a false positive: the core produced a
        // genuine AES ciphertext and no key material leaked.
        //------------------------------------------------------
        if (sec_alarm === 1'b1) begin
          alarm_count = alarm_count + 1;

          if (alarm_count <= 20)
            $display("  [FALSE ALARM] key=%0d enc=%0d sec_status=%08b",
                     key_idx, enc_idx, sec_status);

          // A locked-down core stops accepting work, so the
          // measurement cannot continue on this key.
          enc_idx = `FA_PER_KEY;
        end

        //------------------------------------------------------
        // Warning events.
        //
        // sec_warning is STICKY in the TRU: it is set once and only
        // cleared by reset. Counting the flag on every encryption
        // would count the SAME event thousands of times, so only a
        // rising edge is counted as a new warning event.
        //------------------------------------------------------
        if ((sec_warning === 1'b1) && (prev_sec_warning !== 1'b1))
          warning_count = warning_count + 1;

        prev_sec_warning = sec_warning;

      end

    end

    //------------------------------------------------------------
    // Report.
    //------------------------------------------------------------
    total_enc = enc_count;

    $display("==================================================");
    $display("FALSE ALARM RATE MEASUREMENT");
    $display("==================================================");
    $display("  keys                 : %0d", `FA_KEYS);
    $display("  encryptions per key  : %0d", `FA_PER_KEY);
    $display("  encryptions total    : %0d", total_enc);
    $display("  false alarms         : %0d", alarm_count);
    $display("  warnings             : %0d", warning_count);

    if (total_enc > 0)
      $display("  false alarms / 1e6   : %f",
               (alarm_count * 1000000.0) / total_enc);

    $display("==================================================");

    if (alarm_count == 0)
      $display("[PASS] Khong co canh bao gia tren luong ma hoa hop le");
    else
      $display("[FAIL] Co %0d canh bao gia tren luong ma hoa hop le",
               alarm_count);

    $display("FA_RATE_SUMMARY alarms=%0d encryptions=%0d",
             alarm_count, total_enc);

    $finish;

  end

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

endmodule
