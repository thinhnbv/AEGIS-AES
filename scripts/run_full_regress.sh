#!/usr/bin/env bash
# Run the full NIST MCT regression (10,000 vectors) on the clean core,
# plus the T02 security case, and capture the output.
set -o pipefail

cd /home/thinhnbv/aegis-aes || exit 1

echo "=== STEP 1: regenerate case configs ==="
python3 scripts/gen_case_cfg.py 2>&1 | tail -5

echo
echo "=== STEP 2: T02 security test ==="
timeout 300 make --no-print-directory security CASE=T02_p2_slow_leak 2>&1 | tail -40
echo "T02 exit=$?"

echo
echo "=== STEP 3: FULL 10,000 vector NIST regression on clean core ==="
timeout 1800 make --no-print-directory regress CASE=clean MCT_LIMIT=0 2>&1 | tail -60
echo "regress exit=$?"
