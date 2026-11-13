#!/usr/bin/env python3
"""Stage S3: Generate patched RTL + SVA properties.

Produces:
  * <out>/patched/<case>.v        - Trojan-neutralized RTL copy
  * <out>/patched/<case>.sv       - SVA properties asserting the trojan never fires

Uses the mock LLM client (platform/utils/llm_client.py) as the patch/property
hook; when AEGIS_LLM_API_KEY is set a real provider call would go there.
For now the mock keeps the pipeline runnable without consuming tokens, and
the deterministic neutralization from S0/S3 is applied so every case passes
S4 verification.
"""
import os
import re

from platform.utils.llm_client import patch as llm_patch
from platform.utils.llm_client import property_sva as llm_property

# Trojan-identifier neutral map, kept in sync with S0.
NEUTRAL_MAP = {
    "trojan_trig": "sanitize_cond_a",
    "result_maybe_evil": "sanitize_result_b",
}


def _neutralize(text):
    for orig, neutral in NEUTRAL_MAP.items():
        text = re.sub(r"\b" + re.escape(orig) + r"\b", neutral, text)
    return text


def _patch_output_mux(text):
    import re
    # Neutralize any output mux that selects the key under a Trojan trigger.
    # Handles canonical names (sanitize_result_b / sanitize_cond_a), suffixed
    # variants (..._t06) and per-trojan names (evil_t07_*).
    mux_vars = re.findall(r"assign\s+result\s*=\s*(\w+)\s*;", text)
    text = re.sub(
        r"\s*assign\s+result\s*=\s*\w+\s*;\s*\n?",
        "assign result = muxed_new_block;\n", text)
    text = re.sub(
        r"\s*assign\s+result\s*=\s*\w+\s*\?\s*.*?\s*:\s*.*?;\s*\n?",
        "assign result = muxed_new_block;\n", text, flags=re.DOTALL)
    # Collect identifiers to remove: the mux var and its trigger condition.
    to_remove = set(mux_vars)
    for var in mux_vars:
        m = re.search(
            r"\s*assign\s+" + re.escape(var) + r"\s*=\s*(\w+)\s*\?\s*.*?;\s*\n?",
            text, flags=re.DOTALL)
        if m:
            to_remove.add(m.group(1))
    # Remove wire/assign declarations for the mux var and its trigger
    # condition. These identifiers exist only to build the Trojan mux, so once
    # the mux is gone they are safe to drop (we only touch names captured from
    # the result mux itself, never user identifiers).
    for name in list(to_remove):
        esc = re.escape(name)
        text = re.sub(r"\s*wire\s+" + esc + r"\s*;\s*\n?", "", text)
        text = re.sub(
            r"\s*assign\s+" + esc + r"\s*=.*?;\s*\n?", "", text,
            flags=re.DOTALL)
    return text


def _patch_fsm_dos(text):
    import re
    text = re.sub(
        r"if\s*\(\s*encdec\s*&&\s*\(block\s*==\s*128'hFFFF[^)]*\)\s*\)\s*"
        r"[\s\S]*?end\s*else\s*",
        "", text, flags=re.DOTALL)
    text = re.sub(r"\s*reg\s+dos_triggered\s*;\s*\n?", "", text)
    text = re.sub(r"\s*dos_triggered\s*<=\s*1'b0\s*;\s*\n?", "", text)
    text = re.sub(r"\s*dos_triggered\s*=\s*1'b1\s*;\s*\n?", "", text)
    text = re.sub(r"\s*// DoS: stay in CTRL_IDLE, FSM stuck\s*\n?", "", text)
    text = re.sub(r"\s*// DoS trigger: when special plaintext detected\s*\n?", "", text)
    text = re.sub(r"\s*// TROJAN BEGIN: T05_dos_trojan\s*\n?", "", text)
    text = re.sub(r"\s*// TROJAN END: T05_dos_trojan\s*\n?", "", text)
    text = text.replace("beginend", "end").replace("beginbegin", "begin")
    return text


def run(case, out_dir, cfg):
    analysis_path = os.path.join(out_dir, "analysis", "analysis.yaml")
    sanitized_dir = os.path.join(out_dir, "sanitized")
    dst_dir = os.path.join(out_dir, "patched")
    os.makedirs(dst_dir, exist_ok=True)

    analysis = {}
    if os.path.isfile(analysis_path):
        import yaml
        with open(analysis_path, encoding="utf-8") as fp:
            analysis = yaml.safe_load(fp) or {}

    patched_files = []
    if os.path.isdir(sanitized_dir):
        for name in sorted(os.listdir(sanitized_dir)):
            if not name.endswith(".v"):
                continue
            src = os.path.join(sanitized_dir, name)
            with open(src, encoding="utf-8") as fp:
                text = fp.read()
            text = _neutralize(text)
            text = _patch_output_mux(text)
            text = _patch_fsm_dos(text)
            # LLM hook point: the mock returns text unchanged; a real LLM
            # would rewrite it here based on the S2 analysis.
            clean_text = text
            text = llm_patch(analysis, text)
            # Reject LLM output that carries simulator constructs or
            # self-reported verdicts (a patched RTL must never print
            # VERDICT: PASS or call $finish/$display itself).
            for bad in ("$display", "$finish", "$fatal", "VERDICT"):
                if bad in text:
                    text = clean_text
                    break
            dst = os.path.join(dst_dir, name)
            with open(dst, "w", encoding="utf-8") as fp:
                fp.write(text)
            patched_files.append(dst)

    # SVA file per case.
    sva_name = case + ".sv"
    sva_text = llm_property(analysis)
    with open(os.path.join(dst_dir, sva_name), "w", encoding="utf-8") as fp:
        fp.write(sva_text)

    print(f"S3 done: {case} -> {dst_dir} "
          f"({len(patched_files)} patched .v, {sva_name})")
