#=======================================================================
# zc702.xdc - AEGIS-AES security demo on ZC702 (xc7z020clg484-1)
#
# Pin map theo reference constraint cua board (RDF0171 / UG850):
#   clk_p/clk_n = D18/C19   SYSCLK LVDS on-board (MRCC bank), 200 MHz
#   rst_n       = G19       GPIO_SW_N, active-low, pullup 4.7k
#   uart_rx/tx  = P18/W10   PMod2 (PMod2_2 / PMod2_1), USB-UART ngoai
#   led[0:3]    = E15/D15/W17/W5  PMod1 (PMod1_0..3)
#
# LUU Y:
#  - Pin chan cua J63 la PJTAG - KHONG duoc dua bao mat vao pin chan.
#  - Neu PnR khong dat duoc timing tai 200 MHz (WNS < 0), co the
#    chuyen clock vao PMod2_0 (V7, single-ended LVCMOS25) voi
#    tuyen nhien 50 MHz: binh luan bo phan SYSCLK duoi, huy
#    create_clock o tren, va doi CLK_FREQ trong top_security_demo.v
#    sang 50_000_000 (dong bo cac file copy trong repo).
#=======================================================================

# ---- SYSCLK: 200 MHz LVDS, on-board oscillator (UG850, bank MRCC) ----
set_property PACKAGE_PIN D18 [get_ports clk_p]
set_property PACKAGE_PIN C19 [get_ports clk_n]
set_property IOSTANDARD LVDS_25 [get_ports {clk_p clk_n}]
create_clock -name clk -period 5.000 -waveform {0 2.5} [get_ports clk_p]

# ---- Reset: GPIO_SW_N (active-low, nut DIP SW5) ----
set_property PACKAGE_PIN G19 [get_ports rst_n]
set_property IOSTANDARD LVCMOS25 [get_ports rst_n]

# ---- UART: PMod2, USB-UART ngoai (115200 8N1) ----
set_property PACKAGE_PIN P18 [get_ports uart_rx]
set_property PACKAGE_PIN W10 [get_ports uart_tx]
set_property IOSTANDARD LVCMOS25 [get_ports {uart_rx uart_tx}]

# ---- LEDs user: PMod1 (DS19-22) ----
set_property PACKAGE_PIN E15 [get_ports {led[0]}]
set_property PACKAGE_PIN D15 [get_ports {led[1]}]
set_property PACKAGE_PIN W17 [get_ports {led[2]}]
set_property PACKAGE_PIN W5  [get_ports {led[3]}]
set_property IOSTANDARD LVCMOS25 [get_ports {led[0] led[1] led[2] led[3]}]

# ---- Backup plan (khong hoat dong mac dinh): PMod2_0 single-ended clock
#      neu khong dat duoc 200 MHz - huy create_clock o tren, sua:
#      set_property PACKAGE_PIN V7 [get_ports clk_p]
#      set_property IOSTANDARD LVCMOS25 [get_ports clk_p]
#      (loai port clk_n kho top + xdc)
#      create_clock -name clk -period 20.000 [get_ports clk_p]
