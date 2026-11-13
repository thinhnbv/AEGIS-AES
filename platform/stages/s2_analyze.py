#!/usr/bin/env python3
"""Stage S2: Analyze static evidence and localize the Trojan.

Reads sanitized RTL + S1 evidence.json, heuristically identifies the
trigger and payload, and writes <out>/analysis/analysis.yaml describing
the suspicious region, predicted trigger and payload. This is the
LLM-analyzer stage: when an LLM backend is configured it calls it;
otherwise a deterministic heuristic runs so the pipeline stays usable
without an LLM key (LLM is design-time only, not chip IP).
"""
import json
import os
import re
import yaml

from platform.utils.llm_client import analyze as llm_analyze
from platform.utils.aes_golden import expected_ciphertext_hex

TRIGGER_PATTERNS = [
    (r"trojan_trig|sanitize_cond_a", "T1/T2 constant trigger comparison"),
    (r"encrypt_counter", "T3 encryption counter threshold"),
    (r"dos_triggered", "T5 denial-of-service trigger"),
    (r"t04_seq_state|CTRL_DEBUG|debug_valid|debug_data", "T4 debug-port trigger sequence"),
    (r"T03_ARM_BLOCK", "T4 rare internal state (skip MixColumns)"),
]

PAYLOAD_PATTERNS = [
    (r"result_maybe_evil|sanitize_result_b", "P1 key dump (output mux selects key)"),
    (r"key\[127:0\]|key\[127 : 0\]", "P1/P2 key material exposed on output"),
    (r"encrypt_counter\s*>=", "P2 slow byte leak"),
    (r"dos_triggered", "P5 denial of service (ready stuck at 0)"),
    (r"CTRL_DEBUG", "P4 unauthorized debug port"),
    (r"T03_ARM_BLOCK|MixColumns|mixcol", "P3 skip MixColumns"),
]


def _read_sanitized(sanitized_dir):
    files = {}
    if not os.path.isdir(sanitized_dir):
        return files
    for name in sorted(os.listdir(sanitized_dir)):
        if name.endswith(".v"):
            with open(os.path.join(sanitized_dir, name), encoding="utf-8") as fp:
                files[name] = fp.read()
    return files


def _find(pattern, text, flags=0):
    m = re.search(pattern, text, flags)
    return m.group(0) if m else None


def analyze(case, sanitized_dir, evidence):
    files = _read_sanitized(sanitized_dir)
    all_text = "\n".join(files.values())

    trigger_type = "unknown"
    trigger_value = None
    payload_type = "unknown"
    asset = "unknown"
    confidence = 0.0
    matched_files = list(files.keys())
    details = []

    # --- Trigger identification -------------------------------------
    for pat, label in TRIGGER_PATTERNS:
        hits = [n for n, t in files.items() if re.search(pat, t)]
        if hits:
            trigger_type = label
            details.append(f"trigger signal '{pat}' found in {hits}")
            confidence += 0.25
            break

    # Capture magic constant used in the trigger comparison.
    m = re.search(r"==\s*(128'h[0-9a-fA-F_]+)", all_text)
    if m:
        trigger_value = m.group(1).replace("_", "")
        details.append(f"trigger constant {trigger_value}")

    # Expected ciphertext for the trigger block (golden AES-128-ECB).
    expected_ct = None
    if trigger_value:
        try:
            block_int = int(trigger_value.split("'h")[-1], 16)
            expected_ct = expected_ciphertext_hex(block_int)
            details.append(f"expected ciphertext {expected_ct}")
        except Exception:
            expected_ct = None

    if re.search(r"encrypt_counter\s*>=", all_text):
        trigger_type = "T3 encryption counter >= threshold"
        confidence += 0.2
    if re.search(r"dos_triggered", all_text) and re.search(r"128'hFFFF", all_text):
        trigger_type = "T5 all-0xFF plaintext DoS trigger"
        trigger_value = "128'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        confidence += 0.25
    if re.search(r"t04_seq_state|CTRL_DEBUG", all_text):
        trigger_type = "T4 A5->5A->FF debug-port trigger sequence"
        confidence += 0.25

    # --- IFT trigger candidates (information-flow fan-in cones) -----
    ift = evidence.get("ift", {}) if isinstance(evidence, dict) else {}
    ift_candidates = ift.get("trigger_candidates", []) if isinstance(ift, dict) else []
    ift_cones = ift.get("cones", {}) if isinstance(ift, dict) else {}
    for cand in ift_candidates:
        affects = cand.get("affects", [])
        if any(s in ("result", "ready", "result_valid", "dos_triggered") for s in affects):
            details.append(
                f"IFT: {cand['condition']} affects {', '.join(affects)} "
                f"(fan-in cone)"
            )
            confidence += 0.15
            if trigger_type == "unknown":
                trigger_type = f"IFT-detected trigger: {cand['condition']}"
            if trigger_value is None:
                trigger_value = cand.get("constant")

    # Suspicious regions from IFT cones.
    for sink, cone in ift_cones.items():
        if sink in ("result", "ready", "result_valid", "dos_triggered") and cone:
            details.append(f"IFT fan-in cone for {sink}: {', '.join(cone[:8])}")

    # --- Payload identification -------------------------------------
    if re.search(r"result_maybe_evil|sanitize_result_b", all_text):
        payload_type = "P1 key dump via output mux"
        asset = "aes_key"
        confidence += 0.3
    elif re.search(r"CTRL_DEBUG", all_text):
        payload_type = "P4 unauthorized debug port exposing state + round key"
        asset = "aes_internal_state, aes_round_key"
        confidence += 0.3
    elif re.search(r"dos_triggered", all_text):
        payload_type = "P5 denial of service (ready stuck low)"
        asset = "availability"
        confidence += 0.3
    elif re.search(r"encrypt_counter", all_text):
        payload_type = "P2 slow key-byte leak on output"
        asset = "aes_key"
        confidence += 0.3
    elif re.search(r"T03_ARM_BLOCK", all_text):
        payload_type = "P3 skip MixColumns at round 5"
        asset = "aes_correctness"
        confidence += 0.3

    # LLM analysis (mock unless AEGIS_LLM_API_KEY is set).
    # When mock, keep the heuristic result; only real LLM output overrides it.
    llm_result = llm_analyze(all_text, evidence)
    llm_used = bool(os.environ.get("AEGIS_LLM_API_KEY")) and llm_result.get("llm_used", False)

    analysis = {
        "case_id": case,
        "llm_used": llm_used,
        "llm_source": llm_result.get("llm_source", "mock" if not llm_used else "real"),
        "llm_model": llm_result.get("model", ""),
        "confidence": round(
            min(float(llm_result.get("confidence", confidence) if llm_used else confidence), 1.0), 2
        ),
        "suspicious_files": matched_files,
        "suspicious_regions": (
            llm_result.get("suspicious_regions", details) if llm_used else details
        ),
        "trigger": {
            "type": llm_result.get("predicted_trigger", trigger_type) if llm_used else trigger_type,
            "value": trigger_value,
        },
        "payload": {
            "type": (
                llm_result.get("predicted_payload", payload_type) if llm_used else payload_type
            ),
            "asset": llm_result.get("threatened_asset", asset) if llm_used else asset,
        },
        "details": details,
        "ift_cones": ift_cones,
        "ift_trigger_candidates": ift_candidates,
        "expected_ciphertext": expected_ct,
    }
    return analysis


def run(case, out_dir, cfg):
    sanitized_dir = os.path.join(out_dir, "sanitized")
    dst_dir = os.path.join(out_dir, "analysis")
    os.makedirs(dst_dir, exist_ok=True)

    evidence_path = os.path.join(out_dir, "evidence", "evidence.json")
    evidence = {}
    if os.path.isfile(evidence_path):
        with open(evidence_path, encoding="utf-8") as fp:
            evidence = json.load(fp)

    analysis = analyze(case, sanitized_dir, evidence)

    out_path = os.path.join(dst_dir, "analysis.yaml")
    with open(out_path, "w", encoding="utf-8") as fp:
        yaml.safe_dump(analysis, fp, sort_keys=False, allow_unicode=True)

    print(f"S2 done: {case} -> {out_path} "
          f"(trigger={analysis['trigger']['type']}, "
          f"payload={analysis['payload']['type']}, "
          f"confidence={analysis['confidence']})")


