#-----------------------------------------------------------------------------
# build_zynq.tcl - Vivado batch: SYNC source -> project -> synth -> PnR ->
# bitstream + reports, cho mot ca Trojan.
#
# Chay (Windows/VM - bat file cua Vivado), 1 trong 2 cach:
#   (1) -tclargs truc tiep:
#       vivado -mode batch -nolog -nojournal -source build_zynq.tcl -tclargs T01_p1_key_dump
#   (2) bien moi truong (doi chuan, moa tool nao cung duoc):
#       Windows: set AEGIS_CASE=T01_p1_key_dump && vivado -mode batch -nolog -nojournal -source build_zynq.tcl
#       WSL:     AEGIS_CASE=T01_p1_key_dump vivado -mode batch -nolog -nojournal -source build_zynq.tcl
#
# -tclargs uu tien; neu thieu thi doc AEGIS_CASE; thieu ca hai -> loi.
#
# CASE thuc: T01_p1_key_dump | T02_p2_slow_leak | T03_p3_skip_mixcol
#            T04_p4_debug_port | T05_dos_trojan
#
# Script tu dong doc nguon vao src/ (che do A: sync tu repo; che do B:
# src/ doc lap da hoan chinh - dong nguon voi sync_sources.sh).
# Moi ca = 1 project rieng (aegis_<CASE>) + reports/<CASE>/.
#-----------------------------------------------------------------------------

# ---- doi so + thu muc ----
if {[llength $::argv] >= 1} {
    set case [lindex $::argv 0]
} elseif {[info exists ::env(AEGIS_CASE)]} {
    set case $::env(AEGIS_CASE)
} else {
    error "thieu CASE: dung -tclargs <CASE> hoac bien moi truong AEGIS_CASE"
}

# fpga/xilinx (thuc mu co script)
set here       [file normalize [file dirname [info script]]]
# goc repo (2 cap len tren fpga/xilinx)
set repo_root  [file normalize [file join $here .. ..]]
set src_dir    [file join $here src]
set rep_dir    [file join $here reports $case]
set proj_dir   [file join $here aegis_$case]

# ------------------------------------------------------------------
# Kien dinh source set cho ca $case vao $src_dir.
#
# Co 2 che do (tu dong):
#   A) Repo hoan chinh: $repo_root/rtl/infected/$case/ ton tai
#      -> sync tuong minh (dong nguon voi sync_sources.sh),
#      luon co cau truong + UART + top moi nhat.
#   B) Thu muc doc lap (vd C:\VM_Xilinx\zynq-aegis\src\ - khong
#      co thu muc repo cha): dung src/ da doi sao xuong, chi thay
#      aes_core_tapped.v (trung hop src/ co file cu cua ca khac).
# ------------------------------------------------------------------
set case_core [file join $repo_root rtl infected $case aes_core_tapped.v]

if {[file exists $case_core]} {
    puts "\n\[build_zynq\] case = $case (che do A: sync tu repo $repo_root)"

    file delete -force $src_dir
    file mkdir $src_dir

    # 1) protected path: master rtl/aegis (co cong fsm_state, ORC, KLG full)
    foreach f {aegis_aes_top.v aegis_defs.vh aes_encipher_block.v
               aes_key_mem_tapped.v klg_key_leak_guard.v fic_fsm_integrity.v
               rcm_round_monitor.v orc_output_checker.v red_rare_event.v
               tru_tamper_response.v} {
        file copy -force [file join $repo_root rtl aegis $f] [file join $src_dir $f]
    }

    # 2) sbox/inv_sbox/decipher tu golden
    foreach f {aes_sbox.v aes_inv_sbox.v aes_decipher_block.v} {
        file copy -force [file join $repo_root rtl aes_golden $f] [file join $src_dir $f]
    }

    # 3) core nhiem cua ca (modul aes_core_tapped - duong raw +
    #    protected cung dung mot module nay)
    file copy -force $case_core [file join $src_dir aes_core_tapped.v]

    # 4) UART + FSM (co watchdog T05) tu ban goc fpga/gowin
    foreach f {uart_rx.v uart_tx.v uart_cmd_fsm_security.v} {
        file copy -force [file join $repo_root fpga gowin security_demo src $f] \
                        [file join $src_dir $f]
    }

    # 5) top Zynq (LVDS clk_p/clk_n + CLK_FREQ=200MHz)
    file copy -force [file join $here top_security_demo.v] [file join $src_dir top_security_demo.v]

} else {
    # Che do B: khong co repo (vd chiu y C:\VM_Xilinx\zynq-aegis\src\
    # - thu muc doc lap). src/ phai da du source set hoan chinh do
    # sync_sources.sh tao tren WSL roi doi sao xuong.
    if {![file exists [file join $src_dir top_security_demo.v]]} {
        error "che do B: $src_dir thieu top_security_demo.v - dung src/ hoan chinh do sync_sources.sh tao (truyen thu muc repo WSL vao VM)"
    }
    puts "\n\[build_zynq\] case = $case (che do B: src/ doc lap - CHAU Y: kiem tra src/aes_core_tapped.v da la cua ca $case)"
}

# Bat trai loi song thay: top + include + xdc phai ton tai
foreach f {top_security_demo.v aegis_defs.vh} {
    if {![file exists [file join $src_dir $f]]} {
        error "src/ thieu $f - sync lai nguon (sync_sources.sh $case)"
    }
}

puts "\[build_zynq\] sync xong: [llength [glob -nocomplain [file join $src_dir *.v]]] file .v + 1 file .vh"

# run_failed <run> -> true neu run co ten do that bai (STATUS ne "Failed")
proc run_failed {run} {
    set st [get_property STATUS [get_runs $run]]
    return [string match "*Fail*" $st]
}

file mkdir $rep_dir

# ---- Vivado flow ----
create_project aegis_$case $proj_dir -part xc7z020clg484-1 -force

# Doc RTL (.v thuan, parser Verilog-2001 - da kiem tra compile -g2001
# duoc). aegis_defs.vh phai dong thuc include file de `include bat duoc.
set vfiles [glob -nocomplain [file join $src_dir *.v]]
if {[llength $vfiles] == 0} {
    error "src/ khong co file .v nao - sync lai nguon truoc khi build"
}
add_files $vfiles
add_files [file join $src_dir aegis_defs.vh]
# .vh la Verilog Header cho `include - Vivado 2024.1 khong co property
# is_include_file, dung file_type (tu dong nhan .vh, dat ro de chac chan).
set_property file_type {Verilog Header} [get_files aegis_defs.vh]

# XDC - dat vao constraints set de PnR nhan pin + clock
add_files [file join $here zc702.xdc]

# Top duy nhat - dat tren fileset sources_1 (property 'top' thuoc
# fileset, khong phai project) de Vivado khong doan sai top.
set_property top top_security_demo [get_filesets sources_1]
update_compile_order -fileset sources_1

# ---- Synthesis ----
puts "\n\[build_zynq\] === SYNTHESIS ==="
launch_runs synth_1
wait_on_run synth_1
if {![run_failed synth_1]} {
    open_run synth_1
    report_utilization -file [file join $rep_dir util.rpt]
    report_control_sets -quiet -file [file join $rep_dir control_sets.rpt]
}
if {[run_failed synth_1]} {
    error "SYNTHESIS that bai - xem log trong $proj_dir (report_utilization v.v)."
}

# ---- Implementation (PnR) bitstream ----
puts "\n\[build_zynq\] === PLACEMENT + ROUTING + BITSTREAM ==="
launch_runs impl_1 -to_step write_bitstream
wait_on_run impl_1
if {[run_failed impl_1]} {
    error "IMPLEMENTATION that bai (PnR) - xem log trong $proj_dir."
}

open_run impl_1
file mkdir $rep_dir
report_utilization  -file [file join $rep_dir util.rpt]
report_timing -delay_type max -max_paths 50 -file [file join $rep_dir timing.rpt]
report_timing -delay_type min -max_paths 25 -file [file join $rep_dir timing_min.rpt]
report_methodology -file [file join $rep_dir methodology.rpt]
report_clock_utilization -file [file join $rep_dir clock_util.rpt]
# (khong dung close_run - khong ton tai trong Vivado batch flow)

# Bitstream duoc Vivado viet vao <proj>/<proj>.runs/impl_1/*.bit
# (khong phai $proj_dir/impl_1/ truc tiep) - glob dung thu muc .runs.
set bits [glob -nocomplain [file join $proj_dir *.runs impl_1 *.bit]]
if {[llength $bits] == 0} {
    # Vivado 2024.x co the dung .gen/ - giu fallback cu:
    set bits [glob -nocomplain [file join $proj_dir aegis_$case.gen runs impl_1 *.bit]]
}

puts "\n\[build_zynq\] === XONG $case ==="
if {[llength $bits] > 0} {
    puts "\[build_zynq\] bitstream : [lindex $bits 0]"
} else {
    puts "\[build_zynq\] bitstream : khong tim thay .bit - kiem tra $proj_dir/impl_1/"
}
puts "\[build_zynq\] reports   : $rep_dir/{util,timing,timing_min,methodology,clock_util}.rpt"
puts "\[build_zynq\] kiem tra  : (1) WNS >= 0 trong timing.rpt  (2) LUT/FF/BRAM trong util.rpt"
