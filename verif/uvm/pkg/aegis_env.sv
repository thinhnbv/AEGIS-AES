//==============================================================
// aegis_env.sv
//
// Ties the agent, scoreboard, and coverage together.
//
//   agent.ap  -> scoreboard.ap   (drive results, check them)
//   agent.ap  -> coverage.ap      (sample functional coverage)
//
// A single agent drives both the key and encrypt paths because
// the aegis_aes_top control interface is one control channel.
// (Splitting key/encrypt into two agents would just add
// sequencer traffic with no coverage benefit at this DUT size.)
//==============================================================
`ifndef AEGIS_ENV_SV
`define AEGIS_ENV_SV

class aegis_env extends uvm_env;
  `uvm_component_utils(aegis_env)

  aegis_agent      agent;
  aegis_scoreboard scb;
  aegis_coverage   cov;

  virtual aegis_if vif;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    agent = aegis_agent::type_id::create("agent", this);
    agent.is_active = UVM_ACTIVE;
    scb   = aegis_scoreboard::type_id::create("scb", this);
    cov   = aegis_coverage::type_id::create("cov", this);
  endfunction

  function void connect_phase(uvm_phase phase);
    super.connect_phase(phase);
    agent.vif = vif;

    // The driver publishes every completed txn; both the scoreboard
    // and the functional-coverage collector subscribe.
    agent.drv.ap.connect(scb.ap);
    agent.drv.ap.connect(cov.ap);
  endfunction
endclass

`endif
