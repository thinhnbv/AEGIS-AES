//==============================================================
// tb_top.sv
//
// UVM testbench top for the AEGIS-AES security wrapper.
//
// Owns every simulator-specific concern so the UVM classes stay
// portable:
//   - DUT + interface instantiation
//   - ALL file I/O (contract cfg, clean/trigger vectors, NIST KAT)
//   - building the aegis_case_spec and handing it to the UVM test
//   - clock / reset generation
//
// The DUT source (clean vs an infected case) is chosen at compile
// time by the file list (ModelSim / Icarus), not here. The
// scenario is chosen at run time by the `CASE define:
//   CASE="clean"        -> KAT regression (NIST + clean vector)
//   CASE="fa"           -> false-alarm rate
//   CASE="T0x_..."      -> security case T01..T05
//==============================================================
`timescale 1ns/1ps
`default_nettype none

module tb_top;
  import aegis_uvm_pkg::*;
  import uvm_pkg::*;

  //----------------------------------------------------------
  // Case selection. `make uvm CASE=... defines CASE; default clean.
  //----------------------------------------------------------
  `ifndef CASE
    `define CASE "clean"
  `endif

  //----------------------------------------------------------
  // Clock / reset.
  //----------------------------------------------------------
  logic clk = 1'b0;
  logic rst_n;
  always #5 clk = ~clk;

  //----------------------------------------------------------
  // DUT interface. The DUT connects DIRECTLY to the interface
  // member signals (standard UVM pattern): the driver is the only
  // driver of the stimulus members; observation members carry the
  // DUT outputs. No separate module-scope wires (would be a
  // second, disconnected net).
  //----------------------------------------------------------
  aegis_if u_if (
    .clk(clk),
    .rst_n(rst_n)
  );

  //----------------------------------------------------------
  // DUT (clean or infected - selected by the file list).
  //----------------------------------------------------------
  aegis_aes_top u_dut (
    .clk(clk),
    .rst_n(rst_n),
    .key(u_if.key), .key_valid(u_if.key_valid),
    .data_in(u_if.data_in), .data_in_valid(u_if.data_in_valid),
    .data_out(u_if.data_out), .data_out_valid(u_if.data_out_valid),
    .busy(u_if.busy),
    .sec_alarm(u_if.sec_alarm), .sec_warning(u_if.sec_warning),
    .sec_status(u_if.sec_status)
  );

  //----------------------------------------------------------
  // T02 preload apply (module scope: UVM classes cannot write into
  // a DUT-internal reg). The driver pulses u_if.cp_we/cp_val; this
  // block applies the value to the infected core's encrypt_counter
  // - same mechanism as tb_security.sv. Compiled only for T02
  // builds (-DAEGIS_T02, see the ModelSim scripts).
  //----------------------------------------------------------
  `ifdef AEGIS_T02
    always @(posedge clk) begin
      if (u_if.cp_we)
        u_dut.u_core.encrypt_counter = u_if.cp_val;
    end
  `endif

  //----------------------------------------------------------
  // File I/O + spec construction (TB-only).
  //----------------------------------------------------------
  aegis_case_spec spec;
  string case_str;
  int    cfg_fd, sec_fd, nist_fd, n_scan;
  reg [127:0] f_key, f_pt, f_ct;
  string line;

  function int read_hex_line(input int fd, output reg [127:0] k,
                             output reg [127:0] p,
                             output reg [127:0] c);
    n_scan = $fscanf(fd, "%h %h %h\n", k, p, c);
    return (n_scan == 3);
  endfunction

  task main();
    string clean_vec, t_vec, cfg_path;

    case_str = `CASE;
    spec     = aegis_case_spec::new();
    spec.case_id = case_str;

    //------------------------------------------------------
    // Clean baseline vector (shared by every scenario).
    //------------------------------------------------------
    clean_vec = "verif/vectors/trigger_clean.txt";
    sec_fd = $fopen(clean_vec, "r");
    if (sec_fd == 0)
      $fatal(1, "tb_top: cannot open %s", clean_vec);
    if (!read_hex_line(sec_fd, f_key, f_pt, f_ct))
      $fatal(1, "tb_top: bad clean vector %s", clean_vec);
    $fclose(sec_fd);
    spec.clean_key = f_key;
    spec.clean_pt  = f_pt;
    spec.clean_ct  = f_ct;

    //------------------------------------------------------
    // Pick the scenario.
    //------------------------------------------------------
    if (case_str == "fa") begin
      spec.kind          = CASE_FA;
      spec.fa_iterations = 2000;

    end else if (case_str == "clean" || case_str == "CLEAN") begin
      spec.kind = CASE_CLEAN;
      spec.add_kat(spec.clean_key, spec.clean_pt, spec.clean_ct);
      nist_fd = $fopen("verif/vectors/nist_kat.txt", "r");
      if (nist_fd != 0) begin
        while (!feof(nist_fd))
          if (read_hex_line(nist_fd, f_key, f_pt, f_ct))
            spec.add_kat(f_key, f_pt, f_ct);
        $fclose(nist_fd);
      end

    end else begin
      // A security case: read the contract cfg, then the trigger.
      spec.kind = CASE_SECURITY;
      cfg_path  = {"verif/cfg/", case_str, ".cfg"};
      cfg_fd = $fopen(cfg_path, "r");
      if (cfg_fd == 0)
        $fatal(1, "tb_top: cannot open contract %s", cfg_path);
      while (!feof(cfg_fd)) begin
        line = "";
        if ($fgets(line, cfg_fd) > 0) begin
          if      ($sscanf(line, "trigger_repeat  = %d",
                           spec.trigger_repeat)    == 1) ;
          else if ($sscanf(line, "expected_mask   = %h",
                           spec.expected_mask)     == 1) ;
          else if ($sscanf(line, "expected_latency_cycles = %d",
                           spec.max_latency)       == 1) ;
        end
      end
      $fclose(cfg_fd);
      if (spec.trigger_repeat == 0) spec.trigger_repeat = 1;

      if (case_str == "T04_p4_debug_port" || case_str == "T04") begin
        // T04 arms on a 3-block sequence A5 -> 5A -> FF.
        spec.skip_clean  = 1;
        spec.trig_key    = spec.clean_key;
        spec.trig_blocks.push_back(128'hA500_0000_0000_0000_0000_0000_0000_0001);
        spec.trig_blocks.push_back(128'h5A00_0000_0000_0000_0000_0000_0000_0002);
        spec.trig_blocks.push_back(128'hFF00_0000_0000_0000_0000_0000_0000_0003);
      end
      // T02 slow-leak fires only at the 2^16-th encryption. The real
      // threshold is kept; the counter is preloaded to threshold-1 so
      // `trigger_repeat` encryptions reach it (same acceleration as
      // tb_security.sv). The parameter only exists in the T02 infected
      // core, so this is compile-gated on the -DAEGIS_T02 define that
      // the simulation scripts add for that case.
      else begin
        // T01/T02/T03/T05: a single trigger vector.
        t_vec = {"verif/vectors/trigger_", case_str, ".txt"};
        sec_fd = $fopen(t_vec, "r");
        if (sec_fd == 0)
          $fatal(1, "tb_top: cannot open trigger vector %s", t_vec);
        if (!read_hex_line(sec_fd, f_key, f_pt, f_ct))
          $fatal(1, "tb_top: bad trigger vector %s", t_vec);
        $fclose(sec_fd);
        spec.trig_key    = f_key;
        spec.trig_blocks.push_back(f_pt);

        // T02 slow-leak acceleration (AEGIS_T02 builds only): preload
        // the infected core's encrypt counter to threshold-1 so a
        // handful of encryptions reach the 2^16 threshold (same as
        // tb_security.sv). The parameter only exists on the T02
        // infected core, so this line is compile-gated.
        `ifdef AEGIS_T02
        spec.counter_preload = u_dut.u_core.T02_TRIGGER_COUNT - 16'd1;
        `endif
      end
    end

    //------------------------------------------------------
    // Reset, hand off to UVM.
    //------------------------------------------------------
    rst_n = 1'b0;
    repeat (4) @(negedge clk);
    rst_n = 1'b1;

    uvm_config_db #(aegis_case_spec)::set(uvm_root::get(), "uvm_test_top",
                                          "spec", spec);
    uvm_config_db #(virtual aegis_if)::set(uvm_root::get(), "uvm_test_top",
                                            "vif", u_if);

    run_test("aegis_base_test");

    $display("tb_top: UVM test completed.");
  endtask

endmodule

`default_nettype wire
