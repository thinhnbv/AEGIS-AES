#!/usr/bin/env bash
#---------------------------------------------------------------
# run_all.sh - chay 5 ca Trojan len nhau (moi ca 1 project +
# bitstream + reports). Chay TRONG VM co Vivado.
#
#   cd fpga/xilinx && ./run_all.sh
#
# Moi ca ~5-15 phut (synth + PnR + bitstream). Toan bo ~1h.
# Neu chi can 1 ca:
#   vivado -mode batch -source fpga/xilinx/build_zynq.tcl -tclargs T05_dos_trojan
#---------------------------------------------------------------
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

CASES="T01_p1_key_dump T02_p2_slow_leak T03_p3_skip_mixcol T04_p4_debug_port T05_dos_trojan"
fail=0

for c in $CASES; do
  echo "############################################################"
  echo "# AEGIS-AES / ZC702 - ca $c"
  echo "############################################################"
  if ! vivado -mode batch -nolog -nojournal -source "$HERE/build_zynq.tcl" -tclargs "$c"; then
    echo "[run_all] $c THAT BAI - tiep tuc ca tiep the."
    fail=1
  fi
done

echo
if [ $fail -eq 0 ]; then
  echo "run_all: du 5 ca xong. Kiem tra reports/:"
  echo "  moi ca: fpga/xilinx/reports/<CASE>/{util,timing,methodology}.rpt"
  echo "  bitstream: fpga/xilinx/aegis_<CASE>/impl_1/*.bit"
else
  echo "run_all: CO CA THAT BAI - xem log tren den."
  exit 1
fi
