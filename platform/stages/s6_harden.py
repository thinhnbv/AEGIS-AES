#!/usr/bin/env python3
"""Stage S6: Harden passing SVA into a checker Verilog template.

Reads <out>/patched/<case>.sv (SVA properties from S3) and embeds the
assertion conditions as immediate checks in a structural checker module
(comparator, pulse-sensitive alarm, trigger ROM table). Output:
<out>/harden/<case>_checker.v

The checker can be copied into rtl/aegis/ and wired into aegis_aes_top.
"""
import os
import re


def _read_sva(sva_path):
    """Return list of assertion condition strings extracted from the SVA file.

    Parses lines of the form::

        assert property (!( <cond> |-> <consequent> ));

    and returns <cond> (the antecedent before ``|->``), stripped of any
    surrounding parentheses/whitespace and without a trailing extra ``)``.
    """
    if not os.path.isfile(sva_path):
        return []
    with open(sva_path, encoding="utf-8") as fp:
        text = fp.read()
    conds = []
    for m in re.finditer(
        r"assert\s*property\s*\(\s*!\(\s*(.*?)\s*\|\s*->\s*.*?\)\s*;",
        text,
        flags=re.DOTALL,
    ):
        cond = m.group(1).strip().strip("() ").strip()
        if cond:
            conds.append(cond)
    return conds


def run(case, out_dir, cfg):
    sva_path = os.path.join(out_dir, "patched", case + ".sv")
    dst_dir = os.path.join(out_dir, "harden")
    os.makedirs(dst_dir, exist_ok=True)

    sva_conds = _read_sva(sva_path)

    sva_checks = []
    for cond in sva_conds:
        sva_checks.append(f"    if ({cond}) begin")
        sva_checks.append("      alarm = 1'b1;")
        sva_checks.append(f'      $display("SVA VIOLATION: {cond}");')
        sva_checks.append("    end")

    lines = [
        "/// Checker Verilog template hardened from SVA (stage S6).",
        f"/// Case: {case}",
        "/// Copy into rtl/aegis/ and instantiate in aegis_aes_top.",
        "///",
        "/// This is a structural checker: a comparator watches the trigger",
        "/// signals, and an immediate alarm fires on any key leak (no dwell",
        "/// counter delay, so a single-cycle leak cannot be missed).",
        "",
        "module aegis_trojan_checker #(",
        "    parameter TRIG_WIDTH = 128",
        ") (",
        "    input  wire                   clk,",
        "    input  wire                   rst_n,",
        "    input  wire [TRIG_WIDTH-1:0]  block,",
        "    input  wire                   result_valid,",
        "    input  wire [127:0]           result,",
        "    input  wire [127:0]           key,",
        "    output reg                    alarm,",
        "    output reg [7:0]              alarm_code",
        ");",
        "",
        "  // Comparator: flag when output equals key (key leak).",
        "  wire key_leak = result_valid && (result === key[127:0]);",
        "",
        "  // Pulse-sensitive alarm: fires immediately on key_leak or any SVA violation.",
        "  always @* begin",
        "    alarm = 1'b0;",
        "    if (key_leak) alarm = 1'b1;",
    ]

    if sva_checks:
        lines.append("")
        lines.append("    // SVA assertions from S3 (immediate checks, runnable in simulation).")
        lines.extend(sva_checks)

    lines += [
        "  end",
        "",
        "  // Stickiness: hold alarm_code once raised.",
        "  always @(posedge clk or negedge rst_n) begin",
        "    if (!rst_n) begin",
        "      alarm_code <= 8'd0;",
        "    end else if (alarm) begin",
        "      alarm_code <= 8'h01;",
        "    end",
        "  end",
        "",
        "  // ROM table of known trigger constants (filled in from S2/S3 output).",
        "  // Currently empty: populate with predicted trigger value.",
        "",
        "endmodule",
        "",
    ]

    out_path = os.path.join(dst_dir, case + "_checker.v")
    with open(out_path, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines))

    print(f"S6 done: {case} -> {out_path}")


# Self-check: verify a checker is emitted with immediate alarm and SVA checks.
if __name__ == "__main__" and "s6_harden" in __import__("sys").argv[0]:
    import subprocess
    import sys
    import tempfile

    d = tempfile.mkdtemp()
    patched = os.path.join(d, "patched")
    os.makedirs(patched)
    with open(os.path.join(patched, "T01.sv"), "w") as f:
        f.write("assert property (!( block == 128'hDEADBEEF |-> result === key[127:0] ));\n")
    run("T01", d, {})
    out = os.path.join(d, "harden", "T01_checker.v")
    with open(out, encoding="utf-8") as f:
        text = f.read()
    assert "alarm = 1'b1;" in text, "immediate alarm missing"
    assert "SVA VIOLATION" in text, "SVA check missing"
    assert "dwell_cnt" not in text, "dwell counter should be removed"

    # Each SVA check line must have balanced parentheses (no extra ")").
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("if (") and stripped.endswith("begin"):
            assert stripped.count("(") == stripped.count(")"), f"unbalanced parens: {line}"

    # Generated checker must compile with iverilog.
    proc = subprocess.run(
        ["iverilog", "-g2012", "-o", "/dev/null", out],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"iverilog compile failed: {proc.stderr}"

    print("S6 self-check passed")
