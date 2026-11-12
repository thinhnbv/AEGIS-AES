#=======================================================================
# zc702.xdc - AEGIS-AES security demo on ZC702 (xc7z020clg484-1)
# Pure RTL (khong can Block Design, khong can Zynq PS).
# UART noi truc tiep tu STM32F103 (Blue Pill) qua header J40.
#=======================================================================

# ---- SYSCLK: 200 MHz LVDS, on-board oscillator (UG850, bank MRCC) ----
set_property PACKAGE_PIN D18 [get_ports clk_p]
set_property PACKAGE_PIN C19 [get_ports clk_n]
set_property IOSTANDARD LVDS_25 [get_ports {clk_p clk_n}]
create_clock -name clk -period 5.000 -waveform {0 2.5} [get_ports clk_p]

# ---- Fabric clock: cau chia /8 trong top_security_demo.v (khong MMCM) ----
create_generated_clock -name clk25 -source [get_pins u_clkbuff/O] \
    -divide_by 8 [get_pins div_cnt_reg\[2\]/Q]

# ---- Reset: GPIO_SW_N (chân G19, ACTIVE-HIGH: thả=0, nhan=1) ----
set_property PACKAGE_PIN G19 [get_ports rst_n]
set_property IOSTANDARD LVCMOS25 [get_ports rst_n]

# ---- UART: noi truc tiep tu STM32F103 (Blue Pill) qua header J40 ----
# Header J40 (XADC) tren ZC702:
#   Pin 17 = H22 = FPGA uart_rx  (nhan tu STM32 PA9 / TX)
#   Pin 18 = H17 = FPGA uart_tx  (gui den STM32 PA10 / RX)
#   Pin 16 = GND
set_property PACKAGE_PIN H22 [get_ports uart_rx]
set_property PACKAGE_PIN H17 [get_ports uart_tx]
set_property IOSTANDARD LVCMOS33 [get_ports {uart_rx uart_tx}]

# ---- LEDs user: PMod1 (DS19-22) ----
set_property PACKAGE_PIN E15 [get_ports {led[0]}]
set_property PACKAGE_PIN D15 [get_ports {led[1]}]
set_property PACKAGE_PIN W17 [get_ports {led[2]}]
set_property PACKAGE_PIN W5  [get_ports {led[3]}]
set_property IOSTANDARD LVCMOS25 [get_ports {led[0] led[1] led[2] led[3]}]
