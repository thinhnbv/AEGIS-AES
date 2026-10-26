//==============================================================
// aegis_coverage.sv
//
// Functional-coverage collector for the UVM flow.
//
// DEFAULT build (portable): plain event counters that mirror the
// covergroup bins one-to-one, plus a text report in report_phase.
// This works on EVERY simulator, including the ModelSim
// Intel/Altera edition, where 'covergroup' is not supported
// (vlog-2186: "randomization, coverage or assertion ... only
// supported in Questasim"). The counters are the CV-safe form of
// the same coverage view (per-bin hit counts, dumped to CSV by
// the testplan if desired).
//
// QUESTA build: add -DAEGIS_COVGROUP to the compile and the
// classic 'covergroup'/'coverpoint' model is compiled instead,
// collectable with 'vsim -covd' + 'report coverage -functional'.
//
// Bins (roadmap M2: "sample coverage from observed events"):
//   op mix, silent-vs-attack, per-case status pattern,
//   completion + alarm-latency class
//==============================================================
`ifndef AEGIS_COVERAGE_SV
`define AEGIS_COVERAGE_SV

typedef enum { OP_KAT, OP_SEC, OP_FA, OP_OTHER } aegis_op_kind_e;

class aegis_coverage extends uvm_component;
  `uvm_component_utils(aegis_coverage)

  uvm_analysis_imp #(aegis_txn, aegis_coverage) ap;

  //--------------------------------------------------------
  // Portable event counters (the DEFAULT, works everywhere).
  //--------------------------------------------------------
  int op_kat = 0, op_sec = 0, op_fa = 0, op_oth = 0;
  int silent_yes = 0, silent_no = 0;
  int st_00 = 0, st_01 = 0, st_02 = 0, st_04 = 0, st_08 = 0,
      st_10 = 0, st_11 = 0, st_14 = 0, st_0a = 0, st_0c = 0, st_other = 0;
  int done_ok = 0, done_timeout = 0;
  int lat_01 = 0, lat_short = 0, lat_long = 0, lat_none = 0;
  int total_events = 0;

  function new(string name, uvm_component parent);
    super.new(name, parent);
    ap = new("ap", this);
    `ifdef AEGIS_COVGROUP
      cg_txn     = new();
      cg_monitor = new();
      cg_state   = new();
    `endif
  endfunction

  // Scratch values the (Questa) covergroups sample from.
  aegis_op_kind_e op_kind_scratch;
  bit             silent_scratch;
  bit [7:0]       st_scratch;
  bit             done_scratch;
  bit [1:0]       lat_scratch;

  function void write(aegis_txn t);
    total_events++;

    if      (t.do_ct_check)      op_kat++;
    else if (t.do_mask_check)    op_sec++;
    else if (t.expect_silent)    op_fa++;
    else                         op_oth++;

    if (t.expect_silent) silent_yes++; else silent_no++;

    case (t.got_status)
      8'h00: st_00++;
      8'h01: st_01++;
      8'h02: st_02++;
      8'h04: st_04++;
      8'h08: st_08++;
      8'h10: st_10++;
      8'h11: st_11++;   // T01 / T02
      8'h14: st_14++;   // T03
      8'h0a: st_0a++;   // T04
      8'h0c: st_0c++;   // T05
      default: st_other++;
    endcase

    if (t.completed) done_ok++; else done_timeout++;

    if      (t.alarm_latency < 0)  lat_none++;
    else if (t.alarm_latency <= 1) lat_01++;
    else if (t.alarm_latency <= 5) lat_short++;
    else                            lat_long++;

    `ifdef AEGIS_COVGROUP
      op_kind_scratch = t.do_ct_check ? OP_KAT :
                       t.do_mask_check ? OP_SEC :
                       t.expect_silent ? OP_FA : OP_OTHER;
      silent_scratch  = t.expect_silent;
      st_scratch      = t.got_status;
      done_scratch    = t.completed;
      lat_scratch     = (t.alarm_latency < 0) ? 2'b11 :
                        (t.alarm_latency <= 1) ? 2'b00 :
                        (t.alarm_latency <= 5) ? 2'b01 : 2'b10;
      cg_txn.sample();
      cg_monitor.sample();
      cg_state.sample();
    `endif
  endfunction

  // Text report for the portable counters.
  function void report_phase(uvm_phase phase);
    super.report_phase(phase);
    `uvm_info("COV", $sformatf(
      "COVERAGE ops[kat=%0d sec=%0d fa=%0d oth=%0d] silent[yes=%0d no=%0d] "
      + "status[00=%0d klg=%0d fic=%0d rcm=%0d red=%0d orc=%0d "
      + "t01/02=%0d t03=%0d t04=%0d t05=%0d other=%0d] "
      + "done[ok=%0d timeout=%0d] lat[s0_1=%0d short=%0d long=%0d none=%0d] total=%0d",
      op_kat, op_sec, op_fa, op_oth,
      silent_yes, silent_no,
      st_00, st_01, st_02, st_04, st_08, st_10, st_11, st_14, st_0a, st_0c, st_other,
      done_ok, done_timeout,
      lat_01, lat_short, lat_long, lat_none,
      total_events), UVM_LOW)
  endfunction

  //--------------------------------------------------------
  // QUESTA-class build: real covergroups (-DAEGIS_COVGROUP).
  //--------------------------------------------------------
  `ifdef AEGIS_COVGROUP
  covergroup cg_txn;
    option.per_instance = 1;
    op_kind: coverpoint op_kind_scratch {
      bins kat[] = {OP_KAT};
      bins sec[] = {OP_SEC};
      bins fa [] = {OP_FA};
      bins oth[] = {OP_OTHER};
    }
    silent_expected: coverpoint silent_scratch {
      bins yes = {1};
      bins no  = {0};
    }
    cx: cross op_kind, silent_expected;
  endgroup

  covergroup cg_monitor;
    option.per_instance = 1;
    status: coverpoint st_scratch {
      bins clean = {8'h00};
      bins klg   = {8'h01};
      bins fic   = {8'h02};
      bins rcm   = {8'h04};
      bins red   = {8'h08};
      bins orc   = {8'h10};
      bins t01_02 = {8'h11};
      bins t03   = {8'h14};
      bins t04   = {8'h0a};
      bins t05   = {8'h0c};
      bins other = default;
    }
  endgroup

  covergroup cg_state;
    option.per_instance = 1;
    completed: coverpoint done_scratch { bins ok = {1}; bins timeout = {0}; }
    latency_class: coverpoint lat_scratch {
      bins same_or_1 = {2'b00};
      bins short_lag = {2'b01};
      bins long_lag  = {2'b10};
      bins no_alarm  = {2'b11};
    }
  endgroup
  `endif
endclass

`endif
