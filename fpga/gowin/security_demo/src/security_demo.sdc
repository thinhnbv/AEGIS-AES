//Copyright (C)2014-2026 GOWIN Semiconductor Corporation.
//All rights reserved.
//File Title: Timing Constraints file
//Tool Version: V1.9.9 (64-bit) 
//Created Time: 2026-09-21 00:13:05
create_clock -name clk -period 20 -waveform {0 10} [get_ports {clk}]
