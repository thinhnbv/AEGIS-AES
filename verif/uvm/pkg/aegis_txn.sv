//==============================================================
// aegis_txn.sv
//
// One transaction = one DUT interaction. The key agent drives it
// over the aegis_aes_top control interface using the same
// handshake the plain-SV testbenches use (key_valid / data_in_valid
// pulses + busy handshake).
//
// A txn carries both a STIMULUS (what to send) and an EXPECTATION
// (what the DUT should do), so a single type serves three roles:
//   - KAT      : do_ct_check, expected_ct
//   - security : do_mask_check / expect_alarm, expected_mask,
//                max_alarm_latency
//   - fa-rate  : random key/block, expect clean (no alarm)
//==============================================================
`ifndef AEGIS_TXN_SV
`define AEGIS_TXN_SV

class aegis_txn extends uvm_sequence_item;

  // ---- stimulus ----
  rand bit [127:0] key;
  rand bit [127:0] block;

  // ---- expectation flags ----
  bit do_key_load   = 1;   // load this key before the encrypt op
  bit do_ct_check   = 0;   // expect data_out == expected_ct
  bit do_mask_check = 0;   // expect sec_status covers expected_mask
  bit expect_alarm  = 0;   // security case: an alarm SHOULD fire
  bit expect_silent = 0;   // fa-rate/clean: no alarm allowed

  bit [127:0] expected_ct;   // known-answer (KAT)
  bit [7:0]   expected_mask; // which detectors must be set
  int         max_alarm_latency = 20; // cycles after result_valid to see alarm

  // T02 acceleration: preload the infected core's encrypt_counter to
  // this value right before the encrypt op (simulation-only, set by
  // the security sequence when the spec asks for it).
  int         counter_preload = -1;

  // ---- captured result (filled in by the driver at run time) ----
  bit [127:0] got_ct;
  bit [7:0]   got_status;
  bit         got_alarm;
  int         alarm_latency;  // cycles past output window to see alarm (-1)
  int         payload_cycles; // cycles from op issue to output window
  bit         completed;      // DUT produced the output within timeout

  // Only small (<=32-bit) fields get field automation: UVM's int
  // field op truncates wider packed vectors, and the test never
  // needs do_copy on the 128-bit payloads.
  `uvm_object_utils_begin(aegis_txn)
    `uvm_field_int(expected_mask, UVM_ALL_ON)
    `uvm_field_int(got_status,    UVM_ALL_ON)
    `uvm_field_int(got_alarm,     UVM_ALL_ON)
    `uvm_field_int(alarm_latency, UVM_ALL_ON)
    `uvm_field_int(payload_cycles,UVM_ALL_ON)
    `uvm_field_int(completed,     UVM_ALL_ON)
  `uvm_object_utils_end

  function new(string name = "aegis_txn");
    super.new(name);
  endfunction

  // Constraints keep KAT keys/blocks in the valid hex range and let
  // fa-rate tests randomize freely. The security trigger sequences
  // skip these constraints by driving exact values.
  constraint valid_traffic_c {
    // no restriction: AES-128 accepts any 128-bit key/block
  }

endclass

`endif
