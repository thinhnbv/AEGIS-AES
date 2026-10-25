#!/usr/bin/env python3
"""Validate trigger vector files in verif/vectors/.

Run after checkout or on a fresh clone:  python3 scripts/check_trigger_vectors.py
Exit 0 = all files parse as 3 fields of 32 hex chars, pairs in sync.
Exit 1 = a file is malformed or a pair drifted (e.g. a symlink was
materialized wrong on a non-symlink filesystem).

Pairs (short-name alias, full-name source of truth):
  trigger_T01.txt <-> trigger_T01_p1_key_dump.txt
  trigger_T02.txt <-> trigger_T02_p2_slow_leak.txt
  trigger_T03.txt <-> trigger_T03_p3_skip_mixcol.txt
  trigger_T04.txt <-> trigger_T04_p4_debug_port.txt
  trigger_T05.txt <-> trigger_T05_dos_trojan.txt
  trigger_CLEAN.txt <-> trigger_clean.txt
"""
import re
import sys
from pathlib import Path

PAIRS = [
    ("trigger_T01.txt", "trigger_T01_p1_key_dump.txt"),
    ("trigger_T02.txt", "trigger_T02_p2_slow_leak.txt"),
    ("trigger_T03.txt", "trigger_T03_p3_skip_mixcol.txt"),
    ("trigger_T04.txt", "trigger_T04_p4_debug_port.txt"),
    ("trigger_T05.txt", "trigger_T05_dos_trojan.txt"),
    ("trigger_CLEAN.txt", "trigger_clean.txt"),
]

HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")


def parse(path: Path) -> list[str] | None:
    try:
        text = path.read_text()
    except OSError:
        return None
    lines = [l for l in text.splitlines() if l.strip()]
    fields = []
    for line in lines:
        parts = line.split()
        if len(parts) != 3 or not all(HEX32.match(p) for p in parts):
            return None
        fields.extend(p.lower() for p in parts)
    return fields


def main() -> int:
    vec = Path(__file__).resolve().parent.parent / "verif" / "vectors"
    ok = True

    for short, full in PAIRS:
        a = parse(vec / short)
        b = parse(vec / full)
        if a is None:
            print(f"[FAIL] {short}: not a valid 3x32-hex trigger file")
            ok = False
        if b is None:
            print(f"[FAIL] {full}: not a valid 3x32-hex trigger file")
            ok = False
        elif a is not None and a != b:
            print(f"[FAIL] {short} and {full} drifted (content differs)")
            ok = False
        else:
            print(f"[OK] {short} == {full}")

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
