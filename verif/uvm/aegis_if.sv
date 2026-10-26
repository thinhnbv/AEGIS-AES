//==============================================================
// aegis_if.sv
//
// Interface exposed to the UVM agents. It carries the DUT
// top-level (aegis_aes_top) port signals plus the clock.
//
// The DUT's internal signals (wrapper FSM state, KLG verdict,
// ...) are NOT put on this interface. The functional-coverage
// collector taps them via hierarchical reference from the
// top testbench (ModelSim/Questa support this in simulation),
// keeping the interface a clean, portable "bus" between the
// UVM agent and the DUT.
//
// No clocking blocks on purpose: the drivers drive on
// @(negedge clk), matching the existing plain-SV testbenches,
// which keeps the UVM flow identical to the Icarus baseline.
//==============================================================
`timescale 1ns/1ps
`default_nettype none

// NOTE: port nets use 'wire', not 'logic' - ModelSim (vlog-2892)
// flags variable-typed interface ports but not net-typed ones.
interface aegis_if (input wire clk, input wire rst_n);

  // ---- Stimulus (driven by the UVM driver) ----
  logic [127:0] key;
  logic         key_valid;
  logic [127:0] data_in;
  logic         data_in_valid;

  // ---- Observation (monitored, not driven by the agent) ----
  logic [127:0] data_out;
  logic         data_out_valid;
  logic         busy;
  logic         sec_alarm;
  logic         sec_warning;
  logic [7:0]   sec_status;

  // ---- T02 simulation acceleration (simulation-only) ----
  // UVM classes cannot reach a DUT-internal reg. The driver pulses
  // cp_we with cp_val and the testbench TOP (module scope, where a
  // hierarchical write is legal) applies it to the infected core's
  // encrypt_counter (AEGIS_T02 builds only - see tb_top).
  logic         cp_we = 1'b0;
  logic [15:0]  cp_val = 16'd0;

endinterface

`default_nettype wire
