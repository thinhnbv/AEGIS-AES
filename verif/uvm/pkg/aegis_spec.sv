//==============================================================
// aegis_spec.sv
//
// A per-run "case spec". The testbench top (tb_top.sv) is the only
// component allowed to touch the simulator's file I/O: it reads the
// contract config (verif/cfg/*.cfg), the clean/trigger vectors
// (verif/vectors/*.txt), and the NIST vectors, and fills this spec.
// The UVM test consumes it through config_db. Keeping all file I/O
// in the TB keeps the UVM classes portable and lets the SAME test
// run on ModelSim, Questa, or a Verilator build.
//==============================================================
`ifndef AEGIS_SPEC_SV
`define AEGIS_SPEC_SV

typedef enum { CASE_CLEAN, CASE_FA, CASE_SECURITY } aegis_case_kind_e;

class aegis_case_spec;
  // which scenario the run covers
  aegis_case_kind_e kind;
  string             case_id;

  // clean baseline vector (also the fa-rate / KAT carrier)
  bit[127:0] clean_key, clean_pt, clean_ct;

  // security-case trigger: key + ordered trigger blocks
  bit[127:0] trig_key;
  bit[127:0] trig_blocks[$];
  int        trigger_repeat;
  bit        skip_clean;
  bit[7:0]   expected_mask;
  int        max_latency = 20; // -1 => contract is free-form: only require alarm fired

  // fa-rate
  int        fa_iterations;

  // T02 (slow leak): preload the infected core's encrypt_counter to
  // threshold-1 so `trigger_repeat` encryptions reach the 2^16
  // threshold. -1 = no preload. Applied by the driver (txn field)
  // AFTER the clean baseline op, matching tb_security.sv ordering.
  int        counter_preload = -1;

  // KAT db (clean case): NIST known-answer vectors
  int        n_kat;
  bit[127:0] kat_key [int];
  bit[127:0] kat_pt  [int];
  bit[127:0] kat_ct  [int];

  function new();
    kind = CASE_CLEAN;
    case_id = "clean";
    trigger_repeat = 1;
    skip_clean = 0;
    expected_mask  = 8'h00;
    fa_iterations  = 1000;
    n_kat = 0;
  endfunction

  function void add_kat(bit[127:0] k, bit[127:0] p, bit[127:0] c);
    kat_key[n_kat] = k;
    kat_pt [n_kat] = p;
    kat_ct [n_kat] = c;
    n_kat++;
  endfunction
endclass

`endif
