#!/usr/bin/env python3
"""Stage S1: Static evidence extraction from sanitized RTL.

Compiles sanitized Verilog with iverilog (when available) and extracts
structural hints (output muxes, constant comparisons, FSM states, renamed
Trojan identifiers) that later stages use to localize a potential Trojan.
Writes <out>/evidence/evidence.json.
"""
import json
import os
import re
import subprocess
import sys

from platform.utils.ift import run_ift

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RTL_AEGIS = os.path.join(REPO_ROOT, "rtl", "aegis")
RTL_GOLDEN = os.path.join(REPO_ROOT, "rtl", "aes_golden")


def _find_files(src_dir):
    if not os.path.isdir(src_dir):
        return []
    return [os.path.join(src_dir, n)
            for n in sorted(os.listdir(src_dir)) if n.endswith(".v")]


def _compile(sanitized_dir, work_dir):
    srcs = _find_files(sanitized_dir)
    already = {os.path.splitext(os.path.basename(s))[0] for s in srcs}
    support = []
    for d in (RTL_GOLDEN, RTL_AEGIS):
        for f in _find_files(d):
            base = os.path.splitext(os.path.basename(f))[0]
            if base not in already and base not in ("aegis_aes_top",):
                support.append(f)
    all_srcs = srcs + support
    os.makedirs(work_dir, exist_ok=True)
    out_bin = os.path.join(work_dir, "sim")
    try:
        proc = subprocess.run(
            ["iverilog", "-I", RTL_AEGIS, "-o", out_bin] + all_srcs,
            capture_output=True, text=True, timeout=120,
        )
        return proc.returncode == 0, proc.stderr
    except FileNotFoundError:
        return False, "iverilog not found"
    except Exception as exc:  # pragma: no cover - defensive
        return False, str(exc)


_HEX_CONST = r"(128'h[0-9a-fA-F_]+|64'h[0-9a-fA-F_]+|32'h[0-9a-fA-F_]+|16'h[0-9a-fA-F_]+|8'h[0-9a-fA-F_]+)"


def _extract_text_evidence(sanitized_dir):
    evidence = {
        "modules": [],
        "output_muxes": [],
        "constant_comparisons": [],
        "fsm_states": [],
        "suspicious_signals": [],
    }
    for name in sorted(os.listdir(sanitized_dir)):
        if not name.endswith(".v"):
            continue
        path = os.path.join(sanitized_dir, name)
        with open(path, "r", encoding="utf-8") as fp:
            text = fp.read()
        for m in re.finditer(r"module\s+(\w+)", text):
            evidence["modules"].append({"name": m.group(1), "file": name})
        for m in re.finditer(r"assign\s+(\w+)\s*=\s*([^?]+)\?([^:]+):([^;]+);", text):
            evidence["output_muxes"].append({
                "signal": m.group(1),
                "cond": m.group(2).strip(),
                "true": m.group(3).strip(),
                "false": m.group(4).strip(),
                "file": name,
            })
        for m in re.finditer(r"(==|!=|>=|<=|>|<)\s*(" + _HEX_CONST + r")", text):
            evidence["constant_comparisons"].append({
                "op": m.group(1), "value": m.group(2), "file": name,
            })
        for m in re.finditer(r"localparam\s+(\w+)\s*=\s*([^;]+);", text):
            evidence["fsm_states"].append({
                "name": m.group(1), "value": m.group(2).strip(), "file": name,
            })
        for token in sorted(set(re.findall(r"\b(sanitize_\w+)\b", text))):
            evidence["suspicious_signals"].append(token)
    return evidence


def run(case, out_dir, cfg):
    sanitized_dir = os.path.join(out_dir, "sanitized")
    dst_dir = os.path.join(out_dir, "evidence")
    os.makedirs(dst_dir, exist_ok=True)

    evidence = {"case": case, "compiles": False, "compile_error": ""}
    if os.path.isdir(sanitized_dir):
        ok, err = _compile(sanitized_dir, os.path.join(dst_dir, "compile"))
        evidence["compiles"] = ok
        evidence["compile_error"] = err
        evidence.update(_extract_text_evidence(sanitized_dir))
        evidence["ift"] = run_ift(sanitized_dir)
    else:
        evidence["compile_error"] = f"sanitized dir not found: {sanitized_dir}"

    out_path = os.path.join(dst_dir, "evidence.json")
    with open(out_path, "w", encoding="utf-8") as fp:
        json.dump(evidence, fp, indent=2)

    print(f"S1 done: evidence -> {out_path} (compiles={evidence['compiles']})")


# Self-check: run against the S0 one-shot output.
if __name__ == "__main__" and "s1_static" in __import__("sys").argv[0]:
    sample_dir = os.path.join(REPO_ROOT, "build", "runs", "test_one_shot", "sanitized")
    if not os.path.isdir(sample_dir):
        print("S1 self-check: no sample sanitized dir, skipping")
        sys.exit(0)
    ev = _extract_text_evidence(sample_dir)
    assert isinstance(ev["modules"], list), "modules should be a list"
    assert isinstance(ev["suspicious_signals"], list), "suspicious_signals should be a list"
    print(f"S1 self-check passed: {len(ev['modules'])} module(s), "
          f"{len(ev['output_muxes'])} output mux(es), "
          f"{len(ev['constant_comparisons'])} constant comparison(s), "
          f"{len(ev['suspicious_signals'])} suspicious signal(s)")
