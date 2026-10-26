//==============================================================
// aegis_seqs.sv
//
// Reusable sequences for the three UVM use-cases:
//
//   nist_kat_seq   : replay NIST KAT vectors (known-answer +
//                    no-false-alarm). Vectors are read from the
//                    NIST files via the driver-side loader; here
//                    we accept them as data so the seq stays
//                    simulator-independent.
//   security_case_seq : drive the clean baseline then the case
//                    trigger, expecting the detector mask.
//   fa_rate_seq    : one key reused many times with random
//                    blocks, expecting zero false alarms.
//==============================================================
`ifndef AEGIS_SEQS_SV
`define AEGIS_SEQS_SV

//--------------------------------------------------------------
// Known-answer transaction list loader
//
// Kept separate from the seq so the UVM testbench does not need
// $readmemh of a 10k-line file into a 2D array at elaboration.
// The top testbench reads the vector file into a flat string and
// hands it to the seq.
//--------------------------------------------------------------
class aegis_kat_db;
  int      n_vectors;
  bit[127:0] key [int];
  bit[127:0] pt  [int];
  bit[127:0] ct  [int];

  function new(string name = "aegis_kat_db");
    n_vectors = 0;
  endfunction

  // Load from already-read hex strings (the TB does the file I/O).
  function void add(bit[127:0] k, bit[127:0] p, bit[127:0] c);
    key[n_vectors] = k;
    pt [n_vectors] = p;
    ct [n_vectors] = c;
    n_vectors++;
  endfunction
endclass

//--------------------------------------------------------------
// NIST known-answer + silence
//--------------------------------------------------------------
class nist_kat_seq extends uvm_sequence #(aegis_txn);
  `uvm_object_utils(nist_kat_seq)

  aegis_kat_db db;

  function new(string name = "nist_kat_seq");
    super.new(name);
  endfunction

  task body();
    for (int i = 0; i < db.n_vectors; i++) begin
      aegis_txn t = aegis_txn::type_id::create("kat_txn");
      start_item(t);
      t.key        = db.key[i];
      t.block      = db.pt[i];
      t.do_key_load = 1;
      t.do_ct_check = 1;
      t.expect_silent = 1;   // clean NIST traffic must not alarm
      t.expected_ct = db.ct[i];
      finish_item(t);
    end
  endtask
endclass

//--------------------------------------------------------------
// Security case: baseline clean op, then trigger op
//
// The clean op confirms the DUT still computes the right answer
// before the attack; the trigger op drives the case's activation
// and we check the resulting sec_status against the contract
// expected_mask.
//--------------------------------------------------------------
class security_case_seq extends uvm_sequence #(aegis_txn);
  `uvm_object_utils(security_case_seq)

  // baseline (clean) vector
  bit[127:0] clean_key, clean_pt, clean_ct;
  // trigger: key to reuse + the ordered list of trigger blocks.
  //   - T01/T02/T03/T05: one block, repeated trigger_repeat times
  //   - T04: three blocks A5,5A,FF in order
  bit[127:0] trig_key;
  bit[127:0] trig_blocks[$];
  int        trigger_repeat = 1;
  bit        repeat_each    = 0;  // 1 = repeat whole list trigger_repeat times
  bit        skip_clean     = 0;  // T04: any accepted block arms the trigger
  int        counter_preload = -1; // T02: -1 = none
  // contract
  bit[7:0]   expected_mask;
  int        max_latency   = 20;

  function new(string name = "security_case_seq");
    super.new(name);
  endfunction

  task body();
    aegis_txn c, t;
    bit[127:0] blk;
    int reps;

    reps = repeat_each ? trigger_repeat : 1;

    // ---- clean baseline (skipped for T04: it arms on the first
    // accepted block, so a clean op would corrupt the trigger FSM).
    if (!skip_clean) begin
      c = aegis_txn::type_id::create("clean_txn");
      start_item(c);
      c.key         = clean_key;
      c.block       = clean_pt;
      c.do_key_load = 1;
      c.do_ct_check = 1;
      c.expect_silent = 1;
      c.expected_ct = clean_ct;
      finish_item(c);
    end

    // ---- trigger blocks, in order ----
    if (trig_blocks.size() == 0) begin
      `uvm_error("SECSEQ", "trig_blocks empty - nothing to trigger")
      return;
    end
    for (int rep = 0; rep < reps; rep++) begin
      for (int i = 0; i < trig_blocks.size(); i++) begin
        blk = trig_blocks[i];
        t = aegis_txn::type_id::create("trig_txn");
        start_item(t);
        t.key         = trig_key;
        t.block       = blk;
        // with no clean op, the first trigger txn loads the key
        t.do_key_load = (skip_clean && rep == 0 && i == 0) ? 1 : 0;
        // The detector mask is asserted on the LAST trigger op
        // (the one that completes the trigger). Earlier ops of a
        // sequence (e.g. T04 A5/5A) must not alarm on their own.
        t.do_mask_check = (i == trig_blocks.size() - 1) ? 1 : 0;
        t.expect_alarm  = t.do_mask_check;
        t.expected_mask = expected_mask;
        t.max_alarm_latency = max_latency;
        // preload only on the FIRST trigger op; the counter then
        // saturates at the threshold for the remaining repeats
        t.counter_preload = (rep == 0) ? counter_preload : -1;
        finish_item(t);
      end
    end
  endtask
endclass

//--------------------------------------------------------------
// False-alarm rate: one key, many random blocks
//--------------------------------------------------------------
class fa_rate_seq extends uvm_sequence #(aegis_txn);
  `uvm_object_utils(fa_rate_seq)

  bit[127:0] shared_key;
  int         iterations;

  function new(string name = "fa_rate_seq");
    super.new(name);
    iterations = 1000;
  endfunction

  task body();
    bit[127:0] b;
    aegis_txn k, t;
    int unsigned lcg = 32'h1234_5678 ^ iterations;
    // Deterministic LCG instead of std::randomize: this edition of
    // ModelSim (Intel FPGA) reports randomization as a Questa-only
    // feature (vlog-2186), so the fa-rate flow must stay runnable
    // without simulator-level randomization. The stream is still
    // well-distributed over 128-bit blocks.
    // load the key once
    k = aegis_txn::type_id::create("fa_key");
    start_item(k);
    k.key = shared_key; k.block = shared_key;
    k.do_key_load = 1;
    finish_item(k);

    for (int i = 0; i < iterations; i++) begin
      lcg = (lcg * 32'h1966_0D + 32'h3) >>> 0;
      b = {lcg, lcg, lcg, lcg} ^ (i << 7);
      t = aegis_txn::type_id::create("fa_txn");
      start_item(t);
      t.key         = shared_key;
      t.block       = b;
      t.do_key_load = 0;
      t.expect_silent = 1;   // any alarm here is a false positive
      finish_item(t);
    end
  endtask
endclass

`endif
