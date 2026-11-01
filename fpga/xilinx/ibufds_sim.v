//---------------------------------------------------------------
// ibufds_sim.v - stub IBUFDS cho simulation (Icarus/Verilator).
//
// Vivado build tu co primitive IBUFDS - file nay CHUOC bao giu
// vao project (build_zynq.tcl chi doc fpga/xilinx/src/*.v, va
// sync_sources.sh/sync_sources.bat coi no bi qua). Chu dung nhat
// cho "demo proof": chay iverilog tren cap fpga/xilinx/src/*.v
// - cap day co top_security_demo.v su dung IBUFDS (primitive
// khong co trong Icarus).
//
// Hinh chi: chuyen chuan chenh leu I sang O, bo co N (khong
// can hinh chua trong sim - clock cua TB truyen truc tiep vao
// block duoi, ko di qua top).
//---------------------------------------------------------------
module IBUFDS (
    input  wire I,
    input  wire N,
    output wire O
);
    assign O = I;
endmodule
