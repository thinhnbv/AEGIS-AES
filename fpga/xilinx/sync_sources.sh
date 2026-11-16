#!/usr/bin/env bash
#---------------------------------------------------------------
# sync_sources.sh - doc nguon RTL vao fpga/xilinx/src/ theo mot ca.
#
# Chay tu goc repo, hoac tu bat cu nao - script tu dinh vung goc:
#   ./fpga/xilinx/sync_sources.sh                  # mac dinh: T01
#   ./fpga/xilinx/sync_sources.sh T02_p2_slow_leak
#
# NGUON: ma "that su" la rtl/aegis (master) + rtl/aes_golden
# + cau truong cua ca trong rtl/infected/. Ban copy trong
# fpga/gowin/security_demo/src/ DUNG de lay 3 file UART/FSM
# (dang co watchdog T05). Khong dung nguon Gowin vi ban Gowin
# that kha (thieu cong fsm_state, kha nang ORC, 2-layer KLG).
#---------------------------------------------------------------
set -euo pipefail

CASE="${1:-T01_p1_key_dump}"
HERE="$(cd "$(dirname "$0")" && pwd)"            # .../fpga/xilinx
REPO="$(cd "$HERE/../.." && pwd)"
DEST="$HERE/src"

# Doc case hop le (phai co file trong rtl/infected)
if [ ! -f "$REPO/rtl/infected/$CASE/aes_core_tapped.v" ]; then
  echo "[sync] Loai: khong thay rtl/infected/$CASE/aes_core_tapped.v"
  exit 1
fi

# Xong toan bo src moi lan sync: tranh dat bi (module trung ten)
# va tranh de lai file cu khong thuoc ca hi tai.
rm -rf "$DEST"
mkdir -p "$DEST"

# --- 1) Protected path: master rtl/aegis (co cong fsm_state, ORC, KLG full) ---
cp "$REPO/rtl/aegis/aegis_aes_top.v" "$REPO/rtl/aegis/aegis_defs.vh" \
   "$REPO/rtl/aegis/aes_encipher_block.v" \
   "$REPO/rtl/aegis/aes_key_mem_tapped.v" \
   "$REPO/rtl/aegis/klg_key_leak_guard.v" \
   "$REPO/rtl/aegis/fic_fsm_integrity.v" \
   "$REPO/rtl/aegis/rcm_round_monitor.v" \
   "$REPO/rtl/aegis/orc_output_checker.v" \
   "$REPO/rtl/aegis/red_rare_event.v" \
   "$REPO/rtl/aegis/tru_tamper_response.v" "$DEST/"

# --- 2) Mau giup (sbox/inv_sbox/decipher) tu golden ---
cp "$REPO/rtl/aes_golden/aes_sbox.v" \
   "$REPO/rtl/aes_golden/aes_inv_sbox.v" \
   "$REPO/rtl/aes_golden/aes_decipher_block.v" "$DEST/"

# --- 3) Core nghiem du lieu cua ca (modul aes_core_tapped,
#        dung chung cho ca duong raw va protected) ---
cp "$REPO/rtl/infected/$CASE/aes_core_tapped.v" "$DEST/"

# --- 4) UART + FSM (co watchdog T05) tu ban goc fpga/gowin
#        (working tree) ---
cp "$REPO/fpga/gowin/security_demo/src/uart_rx.v" \
   "$REPO/fpga/gowin/security_demo/src/uart_tx.v" \
   "$REPO/fpga/gowin/security_demo/src/uart_cmd_fsm_security.v" "$DEST/"

# --- 5) Top Zynq (co LVDS clk_p/clk_n + CLK_FREQ=200MHz): copy vao
#        src/ de src/ la source set hoan chinh (Vivado doc nguon
#        duy nhat la src/, kem ca top) ---
cp "$HERE/top_security_demo.v" "$DEST/"

# --- 6) Backup 5 core trojan (de swap cho cac ca khac khi chay tren
#        GUI Vivado - hoi "moi 5 ca, chi doai file core"). Thu muc
#        con de Vivado/iverilog/verilator deu glob "src/*.v"
#        (khong de) nen khong bi thiet ke cu do la "mot ca".
mkdir -p "$DEST/cores"
for c in T01_p1_key_dump T02_p2_slow_leak T03_p3_skip_mixcol \
         T04_p4_debug_port T05_dos_trojan; do
  if [ -f "$REPO/rtl/infected/$c/aes_core_tapped.v" ]; then
    cp "$REPO/rtl/infected/$c/aes_core_tapped.v" "$DEST/cores/${c}_core.v"
  fi
done

echo "[sync] $CASE -> $DEST"
ls -1 "$DEST"
