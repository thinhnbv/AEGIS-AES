#---------------------------------------------------------------
# Makefile for AEGIS-AES FPGA Demo
# Target: ACG525 board with GW5A-25 FPGA
#---------------------------------------------------------------

# Toolchain
GOWIN_TOOLCHAIN := /usr/local/gowin
GW_DE := $(GOWIN_TOOLCHAIN)/IDE/bin/gw_de
GW_FPGA := $(GOWIN_TOOLCHAIN)/IDE/bin/FPGA/impl/gw_fpgapack
GW_LOAD := $(GOWIN_TOOLCHAIN)/Programmer/bin/gw_load

# Project settings
PROJECT := aegis_demo
DEVICE := GW5A-LV25UG324C2/I1
TOP_MODULE := top_demo
DEVICE_FAMILY := GW5A

# Source files
RTL_DIR := ../rtl
UART_DIR := ./uart
BUILD_DIR := ./build
DEVICE_XML := ./constraints/$(DEVICE).xml

# Verilog sources - AES core modules
RTL_SRCS := \
	$(RTL_DIR)/aes_golden/aes_sbox.v \
	$(RTL_DIR)/aes_golden/aes_inv_sbox.v \
	$(RTL_DIR)/aes_golden/aes_decipher_block.v \
	$(RTL_DIR)/aegis/aes_key_mem_tapped.v \
	$(RTL_DIR)/aegis/aes_encipher_block.v \
	$(RTL_DIR)/aegis/aes_core_tapped.v

# UART modules
UART_SRCS := \
	$(UART_DIR)/uart_rx.v \
	$(UART_DIR)/uart_tx.v \
	$(UART_DIR)/uart_cmd_fsm.v

# All FPGA sources
FPGA_SRCS := \
	$(RTL_SRCS) \
	$(UART_SRCS) \
	$(TOP_MODULE).v

# Simulation
IVERILOG := iverilog
VVP := vvp
TB := tb_aegis_demo
WAVES := $(TB).vcd

# Default target
.PHONY: all
all: bitstream

# Build bitstream
bitstream: $(BUILD_DIR)/$(PROJECT).fs

$(BUILD_DIR)/$(PROJECT).fs: $(FPGA_SRCS) $(DEVICE_XML)
	@mkdir -p $(BUILD_DIR)
	$(GW_DE) -d $(DEVICE_FAMILY) -t $(DEVICE) \
		-i $(TOP_MODULE) \
		-p $(DEVICE_XML) \
		-v "$(FPGA_SRCS)" \
		-synth

# Program device
program: $(BUILD_DIR)/$(PROJECT).fs
	$(GW_LOAD) -m GW5A -d $(DEVICE) -s USB -l $<

# Clean
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)/*.vcd $(BUILD_DIR)/run.vvp

# Simulation with Icarus Verilog
sim:
	@mkdir -p $(BUILD_DIR)
	$(IVERILOG) -g2012 -o $(BUILD_DIR)/run.vvp \
		-I$(RTL_DIR) \
		-I$(UART_DIR) \
		$(RTL_SRCS) \
		$(TB).v 2>&1
	cd $(BUILD_DIR) && $(VVP) run.vvp 2>&1

# Run with GTKWave
view: $(BUILD_DIR)/$(WAVES)
	gtkwave $(BUILD_DIR)/$(WAVES) &

# Help
.PHONY: help
help:
	@echo "AEGIS-AES FPGA Demo - Available targets:"
	@echo "  make sim     - Run simulation with Icarus Verilog"
	@echo "  make view    - View waveforms with GTKWave"
	@echo "  make bitstream - Build FPGA bitstream (requires Gowin toolchain)"
	@echo "  make program - Program FPGA device"
	@echo "  make clean   - Clean build files"
