//-----------------------------------------------------------------
// aegis_cfg_reader.vh
//
// Shared helper to read a case contract config file at runtime.
//
// The config files live in verif/cfg/<CASE>.cfg and are generated
// from rtl/infected/<CASE>/ground_truth.yaml by
// scripts/gen_case_cfg.py. They describe what the security monitors
// are CONTRACTUALLY required to do for that case:
//
//   expected_mask           bitmask of detectors that must fire
//   expected_mask_bits      human readable detector list
//   expected_latency        raw contract text (may be prose)
//   expected_latency_cycles integer cycle budget, or -1 if free-form
//   silent_under_nist       true  -> the Trojan must not disturb
//                                    clean NIST traffic at all
//                           false -> the case is allowed to be
//                                    detectable on NIST traffic
//   trigger_repeat          how many times the trigger vector must be
//                            sent before the case counts as detected
//   trigger_seq             path to the trigger vector file
//
// Usage in a testbench:
//
//   `include "aegis_cfg_reader.vh"
//
//   logic [7:0] cfg_expected_mask;
//   integer     cfg_expected_latency;
//   logic       cfg_silent_under_nist;
//
//   initial begin
//     aegis_cfg_read("verif/cfg/T01_p1_key_dump.cfg",
//                    cfg_expected_mask,
//                    cfg_expected_latency,
//                    cfg_silent_under_nist);
//   end
//
// The reader is deliberately line based and field-name driven, so it
// does not depend on the order of the keys in the file.
//
// NOTE: this is a task, not a function, because Icarus Verilog only
// allows input ports on functions.
//-----------------------------------------------------------------
`ifndef AEGIS_CFG_READER_VH
`define AEGIS_CFG_READER_VH

// Read a contract config file.
//
// expected_mask     receives the detector bitmask (0 on failure)
// expected_latency  receives the cycle budget, -1 when the contract
//                   latency is free-form prose
// silent_under_nist receives 1 when the Trojan must stay silent on
//                   clean NIST traffic, 0 otherwise
//
// Sets cfg_ok to 1 on success, 0 when the file could not be opened.
task automatic aegis_cfg_read;
  input  string      path;
  output reg [7:0]   expected_mask;
  output integer     expected_latency;
  output reg         silent_under_nist;
  output integer     trigger_repeat;
  output integer     cfg_ok;

  integer            fd;
  integer            scan;
  integer            done;
  reg [8*256-1:0]    line;
  reg [8*64-1:0]     silent_str;

  begin
    expected_mask     = 8'd0;
    expected_latency  = -1;
    silent_under_nist = 1'b1;
    silent_str        = "true";
    trigger_repeat    = 1;
    done              = 0;
    cfg_ok            = 0;

    fd = $fopen(path, "r");

    if (fd == 0) begin
      $display("[CFG] Khong mo duoc file config: %0s", path);
    end
    else begin
      while (!$feof(fd) && !done) begin
        line = "";
        scan = $fgets(line, fd);

        if (scan != 0) begin
          // The "=" separator lets $sscanf match the whole prefix,
          // so a key is only accepted when it matches exactly.
          if ($sscanf(line, "expected_mask = %h", expected_mask) == 1) begin
            done = 0;
          end
          else if ($sscanf(line, "expected_latency_cycles = %d",
                           expected_latency) == 1) begin
            done = 0;
          end
          else if ($sscanf(line, "silent_under_nist = %s",
                           silent_str) == 1) begin
            done = 0;
          end
          else if ($sscanf(line, "trigger_repeat = %d",
                           trigger_repeat) == 1) begin
            done = 0;
          end
        end
      end

      $fclose(fd);

      silent_under_nist = (silent_str == "true");
      cfg_ok            = 1;

      $display("[CFG] %0s: expected_mask=%08b latency=%0d silent=%0s repeat=%0d",
               path, expected_mask, expected_latency,
               silent_under_nist ? "true" : "false", trigger_repeat);
    end
  end
endtask

`endif
