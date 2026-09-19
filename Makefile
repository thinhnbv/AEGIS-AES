# ====== AEGIS-AES Makefile ======
CASE      ?= clean
SIM       ?= iverilog

RTL_GOLD   = rtl/aes_golden
RTL_AEGIS  = rtl/aegis
RTL_CASE   = rtl/infected/$(CASE)
TB         = verif/tb
BUILD      = build
STAMP     := $(shell date +%Y%m%d_%H%M%S)

SRC_GOLD   = $(wildcard $(RTL_GOLD)/*.v)
SRC_AEGIS  = $(wildcard $(RTL_AEGIS)/*.v)
SRC_CASE   = $(wildcard $(RTL_CASE)/*.v)

ifeq ($(CASE),clean)
	SRC_DUT       = $(SRC_GOLD)
	SRC_AEGIS_DUT = $(SRC_AEGIS)
else
	OVERRIDE       = $(notdir $(SRC_CASE))
	SRC_KEEP       = $(filter-out $(addprefix $(RTL_GOLD)/,$(OVERRIDE)), \
	$(SRC_GOLD))
	SRC_AEGIS_KEEP = $(filter-out $(addprefix $(RTL_AEGIS)/,$(OVERRIDE)), \
	$(SRC_AEGIS))
	SRC_DUT        = $(SRC_KEEP) $(SRC_CASE)
	SRC_AEGIS_DUT  = $(SRC_AEGIS_KEEP)
endif

.PHONY: help golden sim security lint formal all-cases fpga backend campaign report clean

help:
	@echo 'make golden              - kiem tra loi AES goc'
	@echo 'make sim CASE=T01_...    - mo phong chuc nang'
	@echo 'make security CASE=T01   - kich hoat trigger, do latency'
	@echo 'make lint                - Verilator lint tren rtl/aegis'
	@echo 'make formal              - SymbiYosys chay tap SVA'
	@echo 'make all-cases           - chay toan bo benchmark'
	@echo 'make campaign CFG=...    - chay thi nghiem pipeline LLM'
	@echo 'make fpga / backend      - tong hop FPGA / OpenLane'

golden:
	@mkdir -p $(BUILD)
	iverilog -g2012 -o $(BUILD)/golden.out $(SRC_GOLD) $(TB)/tb_aes_golden.sv
	@vvp $(BUILD)/golden.out

sim:
	@mkdir -p $(BUILD)/$(CASE)
	iverilog -g2012 -I$(RTL_AEGIS) -o $(BUILD)/$(CASE)/sim.out $(SRC_DUT) $(SRC_AEGIS_DUT) \
		$(if $(wildcard $(TB)/tb_$(CASE).sv),$(TB)/tb_$(CASE).sv,$(TB)/tb_aegis_top.sv)
	@bash -o pipefail -c 'vvp $(BUILD)/$(CASE)/sim.out | tee $(BUILD)/$(CASE)/sim.log'

# Golden modules needed for security tests (basic components for infected RTL)
SEC_GOLD_SUPPORT = $(RTL_GOLD)/aes_sbox.v $(RTL_GOLD)/aes_inv_sbox.v \
                   $(RTL_GOLD)/aes_key_mem.v \
                   $(RTL_GOLD)/aes_encipher_block.v $(RTL_GOLD)/aes_decipher_block.v

security:
	@mkdir -p $(BUILD)/$(CASE)
ifeq ($(CASE),CLEAN)
	# CLEAN case: aegis RTL + golden support
	iverilog -g2012 -I$(RTL_AEGIS) -DCASE=\"$(CASE)\" -o $(BUILD)/$(CASE)/sec.out \
		$(SRC_AEGIS) \
		$(filter-out $(RTL_GOLD)/aes.v,$(SRC_GOLD)) \
		$(TB)/tb_security.sv
else ifeq ($(CASE),clean)
	# clean case: same as CLEAN
	iverilog -g2012 -I$(RTL_AEGIS) -DCASE=\"$(CASE)\" -o $(BUILD)/$(CASE)/sec.out \
		$(SRC_AEGIS) \
		$(filter-out $(RTL_GOLD)/aes.v,$(SRC_GOLD)) \
		$(TB)/tb_security.sv
else
	# Infected case: aegis RTL (filtered) + infected RTL + golden support
	# Filter out aes_core_tapped.v from aegis since infected provides its own
	# Use infected aes_core_tapped.v for security tests (has tapped ports for monitors)
	iverilog -g2012 -I$(RTL_AEGIS) -DCASE=\"$(CASE)\" -o $(BUILD)/$(CASE)/sec.out \
		$(filter-out $(RTL_AEGIS)/aes_core_tapped.v,$(SRC_AEGIS)) \
		$(filter-out $(RTL_CASE)/aes_core.v,$(wildcard $(RTL_CASE)/*_tapped.v)) \
		$(SEC_GOLD_SUPPORT) \
		$(TB)/tb_security.sv
endif
	@bash -o pipefail -c 'vvp $(BUILD)/$(CASE)/sec.out | tee $(BUILD)/$(CASE)/security.log'

lint:
	verilator --lint-only -Wall -Wno-fatal -Wno-DECLFILENAME \
		-I$(RTL_AEGIS) $(SRC_DUT) $(SRC_AEGIS_DUT) \
		--top-module aegis_aes_top

formal:
	sby -f verif/sva/aegis.sby

all-cases:
	@for c in $$(ls rtl/infected); do \
	echo "=== $$c ==="; \
	$(MAKE) --no-print-directory security CASE=$$c || true; \
	done

campaign:
	python3 platform/run.py --config platform/config/$$(CFG).yaml --out results/runs/$$(STAMP)_$$(CFG)

report:
	python3 scripts/report.py results/runs --out results/tables

fpga:
	$$(MAKE) -C fpga bitstream

backend:
	cd backend/openlane && flow.tcl -design aegis_aes -tag $$(STAMP)

clean:
	rm -rf $(BUILD)
