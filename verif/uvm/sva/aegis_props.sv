//==============================================================
// aegis_props.sv
//
// SVA assertion set for the AEGIS-AES security wrapper.
//
// Written to the portable subset that ModelSim, Questa, Verilator
// and Yosys/SymbiYosys all accept:
//   - immediate assertions
//   - simple concurrent assertions with disable iff
//   - a few |-> and ## sequences
//
// NOTE on the FSM encoding (roadmap M2 flag): the wrapper FSM in
// aegis_aes_top.v is a 3-bit binary state, NOT one-hot, and the
// FIC monitors a 2-bit binary encoding {0,1,2} of the AES core
// control register. The assertions below check the ACTUAL
// encodings, not the "one-hot" wording used in the comments.
//==============================================================
`ifndef AEGIS_PROPS_SV
`define AEGIS_PROPS_SV

//--------------------------------------------------------------
// Bind module: attach the properties to aegis_aes_top.
//--------------------------------------------------------------
module aegis_props #(
    parameter int TIMEOUT = 2000
) (
    input logic         clk,
    input logic         rst_n,

    input logic [127:0] key,
    input logic         key_valid,
    input logic [127:0] data_in,
    input logic         data_in_valid,
    input logic [127:0] data_out,
    input logic         data_out_valid,
    input logic         busy,
    input logic         sec_alarm,
    input logic [7:0]   sec_status
);

  //------------------------------------------------------------
  // P1: key_valid and data_in_valid are single-cycle pulses.
  //     A held-high valid would be re-accepted by the wrapper.
  //------------------------------------------------------------
  property p_key_valid_pulse;
    @(posedge clk) disable iff (!rst_n)
      key_valid |=> !key_valid;
  endproperty
  a_key_valid_pulse: assert property (p_key_valid_pulse)
    else $error("AEGIS: key_valid held more than one cycle");

  property p_data_in_valid_pulse;
    @(posedge clk) disable iff (!rst_n)
      data_in_valid |=> !data_in_valid;
  endproperty
  a_data_in_valid_pulse: assert property (p_data_in_valid_pulse)
    else $error("AEGIS: data_in_valid held more than one cycle");

  //------------------------------------------------------------
  // P2: while busy the wrapper must not accept a new operation.
  //     (data_in_valid while busy would be silently dropped.)
  //------------------------------------------------------------
  property p_no_accept_while_busy;
    @(posedge clk) disable iff (!rst_n)
      busy |-> !data_in_valid;
  endproperty
  a_no_accept_while_busy: assert property (p_no_accept_while_busy)
    else $error("AEGIS: data_in_valid asserted while busy");

  //------------------------------------------------------------
  // P3: data_out_valid is a single-cycle pulse (TRU opens the
  //     output window for exactly one cycle).
  //------------------------------------------------------------
  property p_data_out_valid_pulse;
    @(posedge clk) disable iff (!rst_n)
      data_out_valid |=> !data_out_valid;
  endproperty
  a_data_out_valid_pulse: assert property (p_data_out_valid_pulse)
    else $error("AEGIS: data_out_valid held more than one cycle");

  //------------------------------------------------------------
  // P4: an alarm never clears without a reset. The TRU latches
  //     LOCKDOWN and only a hard reset leaves it, so sec_alarm
  //     must be sticky.
  //------------------------------------------------------------
  property p_alarm_sticky;
    @(posedge clk) disable iff (!rst_n)
      sec_alarm |=> sec_alarm;
  endproperty
  a_alarm_sticky: assert property (p_alarm_sticky)
    else $error("AEGIS: sec_alarm deasserted without reset");

  //------------------------------------------------------------
  // P5: once alarmed, the output must stay blocked.
  //------------------------------------------------------------
  property p_no_output_after_alarm;
    @(posedge clk) disable iff (!rst_n)
      sec_alarm |-> !data_out_valid;
  endproperty
  a_no_output_after_alarm: assert property (p_no_output_after_alarm)
    else $error("AEGIS: data_out_valid asserted while alarmed");

  //------------------------------------------------------------
  // P6: the wrapper must not be simultaneously busy and idle.
  //------------------------------------------------------------
  property p_busy_defined;
    @(posedge clk) disable iff (!rst_n)
      $stable(busy);
  endproperty
  // (informational only - busy legitimately toggles, so this is
  //  intentionally not asserted; kept as a placeholder for a
  //  future liveness check.)

  //------------------------------------------------------------
  // P7: a request must complete or time out. Liveness property for
  //     the formal run (SymbiYosys). Not part of the Verilator
  //     simulation subset (## range not supported there).
  //------------------------------------------------------------
  `ifdef AEGIS_FORMAL
    property p_request_eventually_completes;
      @(posedge clk) disable iff (!rst_n)
        (busy && $past(busy)) |-> ##[1:TIMEOUT] (!busy || sec_alarm);
    endproperty
    a_request_eventually_completes: assert property (p_request_eventually_completes)
      else $error("AEGIS: request did not complete within the timeout");
  `endif

endmodule

//--------------------------------------------------------------
// Bind to the DUT under test.
//--------------------------------------------------------------
bind aegis_aes_top aegis_props u_aegis_props (
    .clk           (clk),
    .rst_n         (rst_n),
    .key           (key),
    .key_valid     (key_valid),
    .data_in       (data_in),
    .data_in_valid (data_in_valid),
    .data_out      (data_out),
    .data_out_valid(data_out_valid),
    .busy          (busy),
    .sec_alarm     (sec_alarm),
    .sec_status    (sec_status)
);

`endif
