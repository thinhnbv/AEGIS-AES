//==============================================================
// aegis_uvm_pkg.sv
//
// UVM environment package for the AEGIS-AES security wrapper.
//
// Order matters: the Accellera UVM core (uvm_pkg) must be compiled
// before this package. Within this package, includes are ordered
// so that each file's dependencies are already declared:
//
//   txn -> spec/agent -> seqs -> scoreboard -> coverage -> env -> test
//
// The interface (aegis_if.sv) is compiled as a separate library
// file (not part of this package), so the virtual-if handle used
// here is provided by the UVM core's `uvm_pkg` + the interface.
//==============================================================
package aegis_uvm_pkg;
  import uvm_pkg::*;
  `include "uvm_macros.svh"

  `include "aegis_txn.sv"
  `include "aegis_spec.sv"
  `include "aegis_agent.sv"
  `include "aegis_seqs.sv"
  `include "aegis_scoreboard.sv"
  `include "aegis_coverage.sv"
  `include "aegis_env.sv"
  `include "aegis_test.sv"

endpackage
