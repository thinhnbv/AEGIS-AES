//==============================================================
// aegis_scoreboard.sv
//
// Independent checker. Consumes the driver-captured txns (via
// the driver's analysis port, which carries the EXPECTATION fields
// intact) and verifies:
//
//   KAT       : got_ct == expected_ct  AND  no alarm on clean ops
//   security  : got_status covers expected_mask  AND  sec_alarm
//               fired within the contract latency budget
//   fa-rate   : every op stays silent (got_alarm == 0)
//
// The scoreboard is the single source of PASS/FAIL; the test's
// report_phase just tallies. This mirrors tb_security's
// fail_count semantics.
//==============================================================
`ifndef AEGIS_SCOREBOARD_SV
`define AEGIS_SCOREBOARD_SV

class aegis_scoreboard extends uvm_scoreboard;
  `uvm_component_utils(aegis_scoreboard)

  uvm_analysis_imp #(aegis_txn, aegis_scoreboard) ap;

  int n_clean_ops, n_clean_pass, n_clean_alarm;
  int n_kat_ops, n_kat_pass;
  int n_sec_ops, n_sec_pass;
  int total, fail;

  function new(string name, uvm_component parent);
    super.new(name, parent);
    ap = new("ap", this);
  endfunction

  function void write(aegis_txn t);
    check_txn(t);
  endfunction

  function void check_txn(aegis_txn t);
    total++;
    if (t.expect_silent) begin
      n_clean_ops++;
      if (t.got_alarm) begin
        n_clean_alarm++;
        `uvm_error("SCB", $sformatf(
          "FALSE ALARM on clean/fa op: got_alarm=1 status=%08b (expected silence)",
          t.got_status))
      end else begin
        n_clean_pass++;
      end
    end

    if (t.do_ct_check) begin
      n_kat_ops++;
      if (t.got_ct !== t.expected_ct) begin
        `uvm_error("SCB", $sformatf(
          "CIPHERTEXT MISMATCH exp=%h got=%h", t.expected_ct, t.got_ct))
      end else begin
        n_kat_pass++;
      end
    end

    if (t.do_mask_check) begin
      n_sec_ops++;
      // The mask must be covered (superset allowed) AND the alarm
      // must have registered.
      if ((t.got_status & t.expected_mask) != t.expected_mask) begin
        `uvm_error("SCB", $sformatf(
          "DETECTOR MASK MISS: expected %08b covered, got status=%08b",
          t.expected_mask, t.got_status))
        fail++;
      end else if (!t.got_alarm) begin
        `uvm_error("SCB", "sec_alarm did not fire for a security case")
        fail++;
      end else begin
        // latency contract
        if (t.alarm_latency < 0) begin
          `uvm_error("SCB", "alarm latency not measured")
          fail++;
        end else if (t.max_alarm_latency >= 0 &&
                t.alarm_latency > t.max_alarm_latency) begin
          `uvm_error("SCB", $sformatf(
            "ALARM LATE: %0d cycles > contract budget %0d",
            t.alarm_latency, t.max_alarm_latency))
          fail++;
        end else begin
          n_sec_pass++;
        end
      end
    end
  endfunction

  function void check_phase(uvm_phase phase);
    super.check_phase(phase);
    `uvm_info("SCB", $sformatf(
      "SUMMARY clean=%0d/%0d kat=%0d/%0d sec=%0d/%0d fail=%0d",
      n_clean_pass, n_clean_ops, n_kat_pass, n_kat_ops,
      n_sec_pass, n_sec_ops, fail), UVM_LOW)
    if (fail > 0)
      `uvm_error("SCB", $sformatf("%0d check(s) FAILED", fail))
  endfunction
endclass

`endif
