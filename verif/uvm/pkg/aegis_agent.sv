//==============================================================
// aegis_agent.sv
//
// Active UVM agent for the aegis_aes_top control interface.
//
//   aegis_driver   : takes a txn off the sequencer, drives the
//                    key/encrypt handshake on aegis_if (the same
//                    handshake proven in tb_security.sv), then
//                    captures the DUT response into txn.got_* and
//                    publishes the txn on an analysis port.
//   aegis_monitor  : passively observes aegis_if and, on each
//                    output window, publishes a lightweight event so
//                    the functional-coverage collector samples
//                    security status independently of the driver.
//
// T05 (DoS) note: when the Trojan holds the core busy forever the
// output window never opens. The driver bounds the wait and flags
// txn.completed=0; the security path's alarm is still caught because
// RCM/zeroize act on the stuck core, so we sample sec_status even
// when the op does not complete. No deadlock: every wait is bounded.
//==============================================================
`ifndef AEGIS_AGENT_SV
`define AEGIS_AGENT_SV

//--------------------------------------------------------------
// Driver
//--------------------------------------------------------------
class aegis_driver extends uvm_driver #(aegis_txn, aegis_txn);
  `uvm_component_utils(aegis_driver)

  virtual aegis_if vif;

  // Every completed txn (expectation + observed fields) is published
  // here for the scoreboard and the coverage collector.
  uvm_analysis_port #(aegis_txn) ap;

  function new(string name, uvm_component parent);
    super.new(name, parent);
    ap = new("ap", this);
  endfunction

  task run();
    aegis_txn txn;
    forever begin
      seq_item_port.get_next_item(txn);
      drive(txn);
      ap.write(txn);
      seq_item_port.item_done();
    end
  endtask

  protected task drive(aegis_txn txn);
    if (vif == null)
      `uvm_fatal("DRV", "vif not set (build_phase mis-wired)")

    // idle stimulus
    vif.key           = '0;
    vif.key_valid     = 1'b0;
    vif.data_in       = '0;
    vif.data_in_valid = 1'b0;

    if (txn.do_key_load) begin
      vif.key       = txn.key;
      vif.key_valid = 1'b1;
      @(negedge vif.clk);
      vif.key_valid = 1'b0;
      begin
        int kw = 0;
        while (vif.busy && kw < 400) begin
          @(negedge vif.clk); kw++;
        end
      end
    end

    // T02 acceleration (same mechanism as tb_security.sv): ask the
    // testbench top to preload the infected core's encrypt counter
    // to threshold-1 so a handful of encryptions reach the 2^16
    // threshold. UVM classes can't reach a DUT-internal reg, so we
    // pulse the interface's cp_we/cp_val and tb_top applies it
    // (module scope, where a hierarchical write is legal).
    if (txn.counter_preload >= 0) begin
      vif.cp_val = txn.counter_preload[15:0];
      vif.cp_we  = 1'b1;
      @(negedge vif.clk);
      vif.cp_we  = 1'b0;
    end

    vif.data_in       = txn.block;
    vif.data_in_valid = 1'b1;
    @(negedge vif.clk);
    vif.data_in_valid = 1'b0;

    // Bounded wait for the TRU-gated output window (one-cycle pulse).
    txn.completed = 1'b0;
    begin
      int w = 0;
      while (!vif.data_out_valid && w < 2000) begin
        @(negedge vif.clk); w++;
      end
      txn.completed      = (vif.data_out_valid === 1'b1);
      txn.payload_cycles = w;
    end

    // Sample result + status on the output window (clean / KAT).
    txn.got_ct     = vif.data_out;
    txn.got_status = vif.sec_status;
    txn.got_alarm  = vif.sec_alarm;

    // Alarm latency: sec_status lags the result by a couple of
    // cycles (TRU NORMAL->SUSPECT->LOCKDOWN). Keep sampling a few
    // cycles past the window so a security case's alarm registers.
    txn.alarm_latency = 0;
    begin
      int a = 0;
      while (!vif.sec_alarm && a < 16) begin
        @(negedge vif.clk); a++;
      end
      txn.alarm_latency = (vif.sec_alarm) ? a : -1;
      txn.got_alarm  = vif.sec_alarm;
      txn.got_status = vif.sec_status;
    end
  endtask
endclass

//--------------------------------------------------------------
// Monitor (passive observer of security status)
//--------------------------------------------------------------
class aegis_monitor extends uvm_monitor;
  `uvm_component_utils(aegis_monitor)

  virtual aegis_if vif;
  uvm_analysis_port #(aegis_txn) ap;

  function new(string name, uvm_component parent);
    super.new(name, parent);
    ap = new("ap", this);
  endfunction

  task run();
    aegis_txn ev;
    // Observe every output window until the TRU latches the alarm
    // (LOCKDOWN: no further output windows exist, so stop here to
    // avoid publishing junk events).
    while (!vif.sec_alarm) begin
      // Bounded wait so a DoS (no output window) cannot hang the
      // monitor; it just observes the stuck state.
      begin
        int w = 0;
        while (!vif.data_out_valid && w < 100) begin
          @(negedge vif.clk); w++;
        end
      end
      ev = aegis_txn::type_id::create("mon_ev");
      ev.got_ct     = vif.data_out;
      ev.got_status = vif.sec_status;
      ev.got_alarm  = vif.sec_alarm;
      ev.completed  = (vif.data_out_valid === 1'b1);
      ap.write(ev);
      // brief settle so we don't double-count a single window
      @(negedge vif.clk);
    end
    `uvm_info("MON", "monitor finished (alarm latched)", UVM_LOW)
  endtask
endclass

//--------------------------------------------------------------
// Agent
//--------------------------------------------------------------
class aegis_agent extends uvm_agent;
  `uvm_component_utils(aegis_agent)

  aegis_driver  drv;
  aegis_monitor mon;
  uvm_sequencer #(aegis_txn, aegis_txn) sqr;

  virtual aegis_if vif;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    drv = aegis_driver::type_id::create("drv", this);
    mon = aegis_monitor::type_id::create("mon", this);
    sqr = uvm_sequencer #(aegis_txn, aegis_txn)::type_id::create("sqr", this);
    if (get_is_active())
      drv.seq_item_port.connect(sqr.seq_item_export);
  endfunction

  function void connect_phase(uvm_phase phase);
    super.connect_phase(phase);
    drv.vif = vif;
    mon.vif = vif;
  endfunction
endclass

`endif
