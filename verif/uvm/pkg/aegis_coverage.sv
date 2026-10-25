//==============================================================
// aegis_coverage.sv
//
// Functional coverage collector. Subscribes to the driver's
// analysis port and samples user-defined covergroups (collected
// by ModelSim via `vsim -covd`, reported with
// `report coverage -functional`).
//
// Bins (roadmap M2: "sample coverage from observed events"):
//   cg_txn     : op kind x silent-expected mix
//   cg_monitor : which detectors fired (sec_status pattern)
//   cg_state   : completion + alarm-latency class
//==============================================================
`ifndef AEGIS_COVERAGE_SV
`define AEGIS_COVERAGE_SV

typedef enum { OP_KAT, OP_SEC, OP_FA, OP_OTHER } aegis_op_kind_e;

class aegis_coverage extends uvm_component;
  `uvm_component_utils(aegis_coverage)

  uvm_analysis_imp #(aegis_txn, aegis_coverage) ap;

  function new(string name, uvm_component parent);
    super.new(name, parent);
    ap       = new("ap", this);
    cg_txn   = new();
    cg_monitor = new();
    cg_state = new();
  endfunction

  // Scratch values the covergroups sample from.
  aegis_op_kind_e op_kind;
  bit             silent_exp;
  bit [7:0]       st;
  bit             done;
  bit [4:0]       lat_class;

  covergroup cg_txn;
    option.per_instance = 1;
    op_kind: coverpoint op_kind {
      bins kat[] = {OP_KAT};
      bins sec[] = {OP_SEC};
      bins fa [] = {OP_FA};
      bins oth[] = {OP_OTHER};
    }
    silent_expected: coverpoint silent_exp {
      bins yes = {1};
      bins no  = {0};
    }
    cx: cross op_kind, silent_expected;
  endgroup

  covergroup cg_monitor;
    option.per_instance = 1;
    status: coverpoint st {
      bins clean   = {8'h00};
      bins klg     = {8'h01};
      bins fic     = {8'h02};
      bins rcm     = {8'h04};
      bins red     = {8'h08};
      bins orc     = {8'h10};
      bins klg_orc = {8'h11};  // T01 / T02
      bins rcm_orc = {8'h14};  // T03
      bins fic_red = {8'h0a};  // T04
      bins rcm_red = {8'h0c};  // T05
      bins other   = default;
    }
  endgroup

  covergroup cg_state;
    option.per_instance = 1;
    completed: coverpoint done { bins ok = {1}; bins timeout = {0}; }
    latency_class: coverpoint lat_class {
      bins same_or_1 = {[0:1]};
      bins short_lag = {[2:5]};
      bins long_lag  = {[6:15]};
      bins no_alarm  = {16};
    }
  endgroup

  function void write(aegis_txn t);
    st    = t.got_status;
    done  = t.completed;
    silent_exp = t.expect_silent;
    op_kind = t.do_ct_check ? OP_KAT :
              t.do_mask_check ? OP_SEC :
              t.expect_silent ? OP_FA : OP_OTHER;
    lat_class = (t.alarm_latency < 0) ? 5'd16 :
                (t.alarm_latency <= 1) ? 5'd0 :
                (t.alarm_latency <= 5) ? 5'd2 :
                (t.alarm_latency <= 15) ? 5'd3 : 5'd4;
    cg_txn.sample();
    cg_monitor.sample();
    cg_state.sample();
  endfunction
endclass

`endif
