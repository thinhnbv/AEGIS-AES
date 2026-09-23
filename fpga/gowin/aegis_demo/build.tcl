set script_dir [file dirname [file normalize [info script]]]

open_project [file join $script_dir aegis_demo.gprj]
run all
