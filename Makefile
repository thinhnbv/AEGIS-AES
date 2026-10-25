# ====== AEGIS-AES Makefile ======
CASE      ?= clean
SIM       ?= iverilog
# Max NIST MCT vectors for `make regress`. 0 = all 10000 (~10 min
# under Icarus). Set e.g. MCT_LIMIT=100 for a quick smoke test.
MCT_LIMIT ?= 0

# False-alarm measurement (make fa-rate).
# FA_KEYS keys are installed in turn, each reused for FA_PER_KEY
# encryptions. 100 x 1000 = 100k encryptions per run; scale up for
# the 1e6 figure quoted in the report.
FA_KEYS   ?= 100
FA_PER_KEY ?= 1000
FA_SEED   ?= 305419896

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

.PHONY: help golden sim security gen-cfg regress regress-all fa-rate lint formal all-cases fpga backend campaign report clean

help:
	@echo 'make golden              - kiem tra loi AES goc'
	@echo 'make sim CASE=T01_...    - mo phong chuc nang'
	@echo 'make security CASE=T01   - kich hoat trigger, do latency'
	@echo 'make gen-cfg             - sinh hop dong case tu ground_truth.yaml'
	@echo 'make regress             - NIST KAT+MCT regression tren core sach'
	@echo 'make regress CASE=T01    - NIST regression tren core nhiem Trojan'
	@echo 'make fa-rate             - do false alarm rate tren luong ma hoa hop le'
	@echo 'make regress-all         - NIST regression cho tat ca ca nhiem'
	@echo 'make lint                - Verilator lint tren rtl/aegis'
	@echo 'make formal              - SymbiYosys chay tap SVA'
	@echo 'make all-cases           - chay toan bo benchmark'
	@echo 'make check-vectors       - kiem tra vector trigger hop le (de chay sau khi checkout)'
	@echo 'make uvm CASE=...        - (Windows) chay UVM+coverage bang ModelSim'
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

#---------------------------------------------------------------
# gen-cfg: compile the case contract into verif/cfg/*.cfg
#
# The contract (which detectors must fire, the detection latency
# budget, whether the Trojan must stay silent on clean NIST traffic)
# lives in rtl/infected/<CASE>/ground_truth.yaml. It is compiled into
# a flat config file that the testbenches read at runtime, so the
# Red team (who writes the Trojan) and the Blue team (who writes the
# checker) cannot silently disagree.
#---------------------------------------------------------------
gen-cfg:
	@python3 scripts/gen_case_cfg.py

# Validate trigger vectors parse and are in sync (catches a checkout
# that materialized a symlink on a non-symlink filesystem).
check-vectors:
	@python3 scripts/check_trigger_vectors.py

security: gen-cfg check-vectors
	@mkdir -p $(BUILD)/$(CASE)
ifeq ($(CASE),CLEAN)
	# CLEAN case: aegis RTL + golden support
	iverilog -g2012 -I$(RTL_AEGIS) -I$(TB) -DCASE=\"$(CASE)\" -o $(BUILD)/$(CASE)/$(CASE).out \
		$(SRC_AEGIS) \
		$(filter-out $(RTL_GOLD)/aes.v,$(SRC_GOLD)) \
		$(TB)/tb_security.sv
else ifeq ($(CASE),clean)
	# clean case: same as CLEAN
	iverilog -g2012 -I$(RTL_AEGIS) -I$(TB) -DCASE=\"$(CASE)\" -o $(BUILD)/$(CASE)/$(CASE).out \
		$(SRC_AEGIS) \
		$(filter-out $(RTL_GOLD)/aes.v,$(SRC_GOLD)) \
		$(TB)/tb_security.sv
else
	# Infected case: aegis RTL (filtered) + infected RTL + golden support
	# Filter out aes_core_tapped.v from aegis since infected provides its own
	# Use infected aes_core_tapped.v for security tests (has tapped ports for monitors)
	iverilog -g2012 -I$(RTL_AEGIS) -I$(TB) -DCASE=\"$(CASE)\" -o $(BUILD)/$(CASE)/$(CASE).out \
		$(filter-out $(RTL_AEGIS)/aes_core_tapped.v,$(SRC_AEGIS)) \
		$(filter-out $(RTL_CASE)/aes_core.v,$(wildcard $(RTL_CASE)/*_tapped.v)) \
		$(SEC_GOLD_SUPPORT) \
		$(TB)/tb_security.sv
endif
	@bash -o pipefail -c 'vvp $(BUILD)/$(CASE)/$(CASE).out | tee $(BUILD)/$(CASE)/$(CASE).log'

#---------------------------------------------------------------
# regress: NIST FIPS-197 regression (KAT 16 + MCT 10000 vectors)
#
# Property under test: a Trojan-infected core must be SILENT on
# clean NIST traffic - ciphertext still correct AND no monitor
# raises a false alarm.
#---------------------------------------------------------------
regress: gen-cfg check-vectors
	@mkdir -p $(BUILD)/$(CASE)
ifeq ($(CASE),CLEAN)
	iverilog -g2012 -I$(RTL_AEGIS) -I$(TB) -DMCT_LIMIT=$(MCT_LIMIT) -DCASE=\"$(CASE)\" -o $(BUILD)/$(CASE)/regress.out \
		$(SRC_AEGIS) \
		$(filter-out $(RTL_GOLD)/aes.v,$(SRC_GOLD)) \
		$(TB)/tb_regress_nist.sv
else ifeq ($(CASE),clean)
	iverilog -g2012 -I$(RTL_AEGIS) -I$(TB) -DMCT_LIMIT=$(MCT_LIMIT) -DCASE=\"$(CASE)\" -o $(BUILD)/$(CASE)/regress.out \
		$(SRC_AEGIS) \
		$(filter-out $(RTL_GOLD)/aes.v,$(SRC_GOLD)) \
		$(TB)/tb_regress_nist.sv
else
	iverilog -g2012 -I$(RTL_AEGIS) -I$(TB) -DMCT_LIMIT=$(MCT_LIMIT) -DCASE=\"$(CASE)\" -o $(BUILD)/$(CASE)/regress.out \
		$(filter-out $(RTL_AEGIS)/aes_core_tapped.v,$(SRC_AEGIS)) \
		$(filter-out $(RTL_CASE)/aes_core.v,$(wildcard $(RTL_CASE)/*_tapped.v)) \
		$(SEC_GOLD_SUPPORT) \
		$(TB)/tb_regress_nist.sv
endif
	@bash -o pipefail -c 'vvp $(BUILD)/$(CASE)/regress.out | tee $(BUILD)/$(CASE)/regress.log'

# Run the NIST regression over every infected case plus the clean core.
regress-all:
	@echo "=== clean ==="
	@$(MAKE) --no-print-directory regress CASE=clean || true
	@for c in $$(ls rtl/infected); do \
	echo "=== $$c ==="; \
	$(MAKE) --no-print-directory regress CASE=$$c || true; \
	done

#---------------------------------------------------------------
# fa-rate: measure the false-alarm rate of the security monitors.
#
# The proposal (muc 9.2) requires the report to state the number of
# false alarms over 1e6 valid encryptions. This target measures it on
# a realistic traffic pattern: one key is installed, then reused for
# many encryptions. That is the pattern the sliding-window detectors
# are designed for.
#
# Overridable:
#   make fa-rate FA_KEYS=200 FA_PER_KEY=5000
#
# The default simulator is Icarus, but Icarus needs several hours for
# 1e6 encryptions. Set SIM=verilator for a compiled run that finishes
# in seconds:
#   make fa-rate SIM=verilator FA_KEYS=200 FA_PER_KEY=5000
#---------------------------------------------------------------
fa-rate:
	@mkdir -p $(BUILD)/fa_rate
ifeq ($(SIM),verilator)
	verilator --binary --timing -Wno-fatal -Wno-DECLFILENAME \
		-I$(RTL_AEGIS) -I$(TB) \
		--top-module tb_fa_rate \
		-DFA_KEYS=$(FA_KEYS) -DFA_PER_KEY=$(FA_PER_KEY) \
		-DFA_SEED=$(FA_SEED) \
		-Mdir $(BUILD)/fa_rate/obj -o fa_rate_v \
		$(SRC_AEGIS) \
		$(filter-out $(RTL_GOLD)/aes.v,$(SRC_GOLD)) \
		$(TB)/tb_fa_rate.sv
	@bash -o pipefail -c '$(BUILD)/fa_rate/obj/fa_rate_v | tee $(BUILD)/fa_rate/fa_rate.log'
else
	iverilog -g2012 -I$(RTL_AEGIS) -I$(TB) \
		-DFA_KEYS=$(FA_KEYS) -DFA_PER_KEY=$(FA_PER_KEY) \
		-DFA_SEED=$(FA_SEED) \
		-o $(BUILD)/fa_rate/fa_rate.out \
		$(SRC_AEGIS) \
		$(filter-out $(RTL_GOLD)/aes.v,$(SRC_GOLD)) \
		$(TB)/tb_fa_rate.sv
	@bash -o pipefail -c 'vvp $(BUILD)/fa_rate/fa_rate.out | tee $(BUILD)/fa_rate/fa_rate.log'
endif

lint:
	verilator --lint-only -Wall -Wno-fatal -Wno-DECLFILENAME \
		-I$(RTL_AEGIS) $(SRC_DUT) $(SRC_AEGIS_DUT) \
		--top-module aegis_aes_top
# UVM + functional-coverage flow. ModelSim (Altera/Intel, Windows)
# is the target simulator; the script lives in verif/uvm/scripts/
# and is meant to be run from the repo root on Windows
# (vsim -c -do "do verif/uvm/scripts/aegis_uvm.tcl").
# This target only ensures the pinned UVM-core submodule is present.
uvm:
	@git submodule update --init --recursive 2>/dev/null || true
	@echo "UVM flow runs under ModelSim on Windows:"
	@echo "  vsim -c -do \"set aegis_case $(or $(CASE),clean); do verif/uvm/scripts/aegis_uvm.tcl\""
	@echo "  (CASE: clean | fa | T01_p1_key_dump ... T05_dos_trojan)"

formal:
	@command -v sby >/dev/null 2>&1 || { echo "sby (yosys-sby) chua cai - chay: sudo apt install yosys-sby"; exit 1; }
	sby -f verif/sva/aegis.sby

all-cases:
	@failed=0; \
	for c in $$(ls rtl/infected); do \
	  echo "=== $$c ==="; \
	  if $(MAKE) --no-print-directory security CASE=$$c; then \
	    echo "[OK] $$c"; \
	  else \
	    echo "[FAIL] $$c"; failed=1; \
	  fi; \
	done; \
	echo "===================="; \
	if [ $$failed -eq 0 ]; then \
	  echo "[ALL-CASES] PASS: all cases detected"; \
	else \
	  echo "[ALL-CASES] FAIL: one or more cases failed"; \
	  exit 1; \
	fi

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
