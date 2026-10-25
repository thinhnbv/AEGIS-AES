#================================================================
# aegis_uvm.tcl
#
# AEGIS-AES UVM flow for ModelSim (Altera/Intel edition).
# Run from the repository root so the relative paths resolve.
#
# Interactive (ModelSim console):
#   > set aegis_case "clean"
#   > do verif/uvm/scripts/aegis_uvm.tcl
#
# Batch (cmd.exe, no GUI):
#   vsim -c -do "set aegis_case clean; do verif/uvm/scripts/aegis_uvm.tcl; quit"
#
# The DUT source list depends on the case, so the flow
# recompiles on every run (UVM + RTL is small; ~2 min).
#================================================================

if {![info exists aegis_case]} { set aegis_case "clean" }

set UVM_SRC   verif/uvm/uvm-core/src
set RTL_AEGIS rtl/aegis
set RTL_GOLD  rtl/aes_golden

# Case names that use the infected core from rtl/infected/<case>/
set CASES {T01_p1_key_dump T01 T02_p2_slow_leak T02 \
           T03_p3_skip_mixcol T03 T04_p4_debug_port T04 \
           T05_dos_trojan T05}

# ---------------------------------------------------------------
# DUT source list
#
# clean/fa : aegis RTL + golden datapath support
# T0x      : aegis RTL minus aes_core_tapped.v, plus the infected
#            aes_core_tapped.v from rtl/infected/<case>/
#            (same override rule as the Makefile 'security' target)
# ---------------------------------------------------------------
set AEGIS_RTL_LIST {
    aegis_aes_top.v
    aes_core_tapped.v
    aes_key_mem_tapped.v
    aes_encipher_block.v
    fic_fsm_integrity.v
    klg_key_leak_guard.v
    orc_output_checker.v
    rcm_round_monitor.v
    red_rare_event.v
    tru_tamper_response.v
}
set GOLD_SUPPORT { aes_sbox.v aes_inv_sbox.v aes_decipher_block.v }

set is_case 0
foreach c $CASES { if {$aegis_case eq $c} { set is_case 1 } }

set rtl_files {}
foreach f $AEGIS_RTL_LIST {
    if {$is_case && $f eq "aes_core_tapped.v"} { continue }
    lappend rtl_files "$RTL_AEGIS/$f"
}
if {$is_case} {
    lappend rtl_files "rtl/infected/$aegis_case/aes_core_tapped.v"
}
foreach f $GOLD_SUPPORT { lappend rtl_files "$RTL_GOLD/$f" }

# T02's tb_top counter-preload is compile-gated on AEGIS_T02
set inc_defines ""
if {$aegis_case eq "T02_p2_slow_leak" || $aegis_case eq "T02"} {
    set inc_defines " -DAEGIS_T02"
}

# ---------------------------------------------------------------
# Compile
# ---------------------------------------------------------------
echo "=== AEGIS UVM build: case=$aegis_case ==="

if {![file isdirectory work]} {
    vlib work
}
vmap work

# 1. Accellera UVM core (pinned submodule).
#
# NOTE: no -assert flag. In ModelSim (2020.1 Intel FPGA Edition and
# later) SystemVerilog assertion compilation is enabled by default
# under -sv; the -assert flag does not exist in this tool build.
vlog -sv -work work +incdir+$UVM_SRC $UVM_SRC/uvm_pkg.sv
if {$::error_info != ""} {
    echo "ERROR: UVM core failed to compile - see messages above"
    exit 1
}

# 2. Interface, UVM env package, SVA, testbench top, DUT RTL.
vlog -sv -work work \
     +incdir+$RTL_AEGIS +incdir+$RTL_GOLD +incdir+verif/uvm/pkg \
     +incdir+$UVM_SRC \
     $inc_defines \
     [join $rtl_files] \
     verif/uvm/aegis_if.sv \
     verif/uvm/pkg/aegis_uvm_pkg.sv \
     verif/uvm/sva/aegis_props.sv \
     verif/uvm/tb_top.sv

# ---------------------------------------------------------------
# Simulate with functional-coverage collection
# ---------------------------------------------------------------
echo "=== vsim -covd (case=$aegis_case) ==="

vsim -covd -sv -work work tb_top

run -all

# ---------------------------------------------------------------
# Functional-coverage report
# ---------------------------------------------------------------
echo "=== Functional coverage (case=$aegis_case) ==="
report coverage -functional
echo "=== done: case=$aegis_case ==="
