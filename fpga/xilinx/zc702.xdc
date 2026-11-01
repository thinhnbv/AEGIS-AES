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
#  - Fabric chay 25 MHz (chia /8 boi div_cnt trong top, khong can MMCM) -
#    vi duong critical ~28.7ns, 200 MHz dat khong (WNS -23ns trong log
#    Xilinx). Chuan nguon clk (5ns) chi chay IBUFDS + cau chia - dat du.
#  - Neu WNS van am tai 25 MHz: chuyen nguon sang PMod2_0 (V7, 50 MHz)
#    va doi cau chia trong top sang /2 - xem "backup plan" cuoi file.
#=======================================================================

# ---- SYSCLK: 200 MHz LVDS, on-board oscillator (UG850, bank MRCC) ----
# Top co IBUFDS (clk_p/clk_n) => day clock tren port clk_p,
# tool tu hiep nhat differential pair (khong bi IOSTDTYPE-1).
set_property PACKAGE_PIN D18 [get_ports clk_p]
set_property PACKAGE_PIN C19 [get_ports clk_n]
set_property IOSTANDARD LVDS_25 [get_ports {clk_p clk_n}]
create_clock -name clk -period 5.000 -waveform {0 2.5} [get_ports clk_p]

# ---- Fabric clock: cau chia /8 trong top_security_demo.v (khong MMCM) ----
# clk_core = div_cnt_reg[2].Q = 200/8 = 25 MHz (chu ky 40ns) - chang
# toan bo fabric (UART + raw/protected + FSM). Critical path ~28.7ns
# nen 200 MHz dat khong; chu ky 40ns co le margin ~11ns.
# Ghi: Vivado tu suy ra pattern chia tren register, dong
# create_generated_clock chi dinh chu ky + dat ten de report timing ro riet.
# Neu PnR loi "pin khong tim thay" (ten register bi doi), xoa duoc dong
# nay - timing van duoc phan tich tu clock suy ra.
create_generated_clock -name clk25 -source [get_clocks clk] \
    -divide_by 8 [get_pins div_cnt_reg\[2\].Q]

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

# ---- Backup plan (khong hoat dong mac dinh): PMod2_0 single-ended 50 MHz
#      dung neu WNS van am tai 25 MHz - huy block SYSCLK tren, huy dong
#      create_generated_clock clk25, sua:
#      set_property PACKAGE_PIN V7 [get_ports clk_p]
#      set_property IOSTANDARD LVCMOS25 [get_ports clk_p]
#      (loai port clk_n kho top + xdc)
#      create_clock -name clk -period 20.000 [get_ports clk_p]
#      # va trong top: cau chia /2 thay vi /8 (clk_core = div_cnt[1]),
#      # CLK_FREQ giu nguyen = 25_000_000.
