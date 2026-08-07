#!/usr/bin/env bash
set -e
TMP=$(mktemp -d)
git clone --depth 1 https://github.com/secworks/aes "$TMP"
mkdir -p rtl/aes_golden
cp "$TMP"/src/rtl/aes*.v  rtl/aes_golden/
cp "$TMP"/LICENSE         rtl/aes_golden/
mkdir -p verif/tb_golden
cp "$TMP"/src/tb/tb_aes*.v verif/tb_golden/
rm -rf "$TMP"
echo 'Da lay xong loi golden. Chay: make golden'
