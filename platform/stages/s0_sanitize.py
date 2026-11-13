#!/usr/bin/env python3
"""Stage S0: Sanitize infected RTL.

Reads Verilog files from rtl/infected/<CASE>/, strips Trojan hint comments
and renames Trojan-specific identifiers to neutral names, then writes the
sanitized copy to <out>/sanitized/. A mapping file records original ->
neutral names so later stages can refer back if needed.

Only files with .v extension are processed; ground_truth.yaml is never
touched by this stage.
"""
import os

NEUTRAL_MAP = {
    "trojan_trig": "sanitize_cond_a",
    "result_maybe_evil": "sanitize_result_b",
}


def _sanitize_text(text):
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        # Only drop Trojan hint comment lines; keep all code intact so the
        # design still parses. Identifier renaming happens next.
        if stripped.startswith("//") and (
            "TROJAN BEGIN" in stripped or "TROJAN END" in stripped
        ):
            continue
        lines.append(line)
    return "\n".join(lines)


def _rename_identifiers(text):
    for orig, neutral in NEUTRAL_MAP.items():
        text = text.replace(orig, neutral)
    return text


def run(case, out_dir, cfg):
    src_dir = os.path.join("rtl", "infected", case)
    dst_dir = os.path.join(out_dir, "sanitized")
    os.makedirs(dst_dir, exist_ok=True)

    mapping_path = os.path.join(dst_dir, "sanitize_map.txt")
    with open(mapping_path, "w", encoding="utf-8") as map_fp:
        map_fp.write("original -> neutral\n")
        for orig, neutral in sorted(NEUTRAL_MAP.items()):
            map_fp.write(f"{orig} -> {neutral}\n")

    for name in sorted(os.listdir(src_dir)):
        if not name.endswith(".v"):
            continue
        src_path = os.path.join(src_dir, name)
        with open(src_path, "r", encoding="utf-8") as fp:
            raw = fp.read()

        cleaned = _sanitize_text(raw)
        cleaned = _rename_identifiers(cleaned)

        dst_path = os.path.join(dst_dir, name)
        with open(dst_path, "w", encoding="utf-8") as fp:
            fp.write(cleaned)

    print(f"S0 done: {len([n for n in os.listdir(src_dir) if n.endswith('.v')])} file(s) sanitized -> {dst_dir}")


# Self-check: run this module directly with a tiny inline example.
if __name__ == "__main__" and "s0_sanitize" in __import__("sys").argv[0]:
    sample = """module top(
  input wire clk,
  // TROJAN BEGIN: leak key
  wire trojan_trig = (block == 128'hdeadbeef);
  assign result_maybe_evil = trojan_trig ? key : block;
  // ===== TROJAN END =====
  output wire [127:0] result
);
  assign result = block;
endmodule
"""
    expected_neutral = "sanitize_cond_a"
    expected_result_neutral = "sanitize_result_b"
    cleaned = _sanitize_text(sample)
    assert "TROJAN BEGIN" not in cleaned, "trojan block comment not removed"
    assert "TROJAN END" not in cleaned, "trojan end comment not removed"
    assert "wire trojan_trig" in cleaned, "code line with trojan_trig should remain"
    assert "assign result_maybe_evil" in cleaned, "code line with result_maybe_evil should remain"
    cleaned = _rename_identifiers(cleaned)
    assert expected_neutral in cleaned, "neutral name missing"
    assert expected_result_neutral in cleaned, "neutral result name missing"
    print("S0 self-check passed")
