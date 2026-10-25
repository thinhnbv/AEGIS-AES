//==============================================================
// aegis_test.sv
//
// UVM test. Consumes the aegis_case_spec + virtual interface from
// config_db (both stashed by tb_top) and runs the matching
// scenario:
//
//   CASE_CLEAN    -> nist_kat_seq    (KAT known-answer + silence)
//   CASE_SECURITY -> security_case_seq (clean + trigger, mask)
//   CASE_FA       -> fa_rate_seq     (reused key, zero false alarms)
//==============================================================
`ifndef AEGIS_TEST_SV
`define AEGIS_TEST_SV

class aegis_base_test extends uvm_test;
  `uvm_component_utils(aegis_base_test)

  aegis_env       env;
  aegis_case_spec spec;
  virtual aegis_if vif;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    if (!uvm_config_db #(aegis_case_spec)::get(this, "", "spec", spec))
      `uvm_fatal("TEST", "aegis_case_spec not in config_db (tb_top mis-wired)")
    if (!uvm_config_db #(virtual aegis_if)::get(this, "", "vif", vif))
      `uvm_fatal("TEST", "virtual aegis_if not in config_db (tb_top mis-wired)")

    env = aegis_env::type_id::create("env", this);
    env.vif = vif;
  endfunction

  task main_phase(uvm_phase phase);
    case (spec.kind)
      CASE_CLEAN:    do_kat();
      CASE_SECURITY: do_security();
      CASE_FA:       do_fa();
      default: `uvm_fatal("TEST", $sformatf("unknown case kind %s", spec.kind.name))
    endcase
  endtask

  protected task do_kat();
    nist_kat_seq seq = nist_kat_seq::type_id::create("seq");
    aegis_kat_db db = aegis_kat_db::new("db");
    for (int i = 0; i < spec.n_kat; i++)
      db.add(spec.kat_key[i], spec.kat_pt[i], spec.kat_ct[i]);
    seq.db = db;
    seq.start(env.agent.sqr);
  endtask

  protected task do_security();
    security_case_seq seq = security_case_seq::type_id::create("seq");
    seq.clean_key      = spec.clean_key;
    seq.clean_pt       = spec.clean_pt;
    seq.clean_ct       = spec.clean_ct;
    seq.trig_key       = spec.trig_key;
    seq.trig_blocks    = spec.trig_blocks;
    seq.trigger_repeat = spec.trigger_repeat;
    seq.repeat_each    = 1;
    seq.skip_clean     = spec.skip_clean;
    seq.expected_mask  = spec.expected_mask;
    seq.max_latency    = spec.max_latency;
    seq.counter_preload = spec.counter_preload;
    seq.start(env.agent.sqr);
  endtask

  protected task do_fa();
    fa_rate_seq seq = fa_rate_seq::type_id::create("seq");
    seq.shared_key = spec.clean_key;
    seq.iterations = spec.fa_iterations;
    seq.start(env.agent.sqr);
  endtask
endclass

`endif
