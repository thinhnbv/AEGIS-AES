#!/usr/bin/env python3
"""LLM client wrapper for the AEGIS-AES pipeline.

Primary mode: mock (no API key). Returns a deterministic, self-consistent
analysis + patch so the pipeline runs end-to-end without consuming tokens.
If AEGIS_LLM_API_KEY is set, a real provider call (OpenAI-compatible chat
completion endpoint via stdlib urllib) is used instead. LLM is design-time
only, not chip IP.
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request

_USE_MOCK = not bool(os.environ.get("AEGIS_LLM_API_KEY"))

_API_BASE = os.environ.get("AEGIS_LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
_API_MODEL = os.environ.get("AEGIS_LLM_MODEL", "agentgw-opus-4-8")
_API_KEY = os.environ.get("AEGIS_LLM_API_KEY", "")
_ALLOW_OUTBOUND = os.environ.get("AEGIS_LLM_ALLOW_OUTBOUND", "0") == "1"
_ALLOWED_HOSTS = ("api.agentgw.cloud", "api.openai.com")
BACKEND = os.environ.get("AEGIS_LLM_BACKEND", "real")

# Call counter for credit tracking across the pipeline run.
_LLM_CALL_COUNT = 0


def _chat(system_prompt, user_prompt, temperature=0.2, max_tokens=1024):
    """Call an OpenAI-compatible chat completion endpoint. Returns the
    assistant message content as a string, or None on failure."""
    global _LLM_CALL_COUNT
    if BACKEND == "static":
        print("[LLM] backend=static: blocking outbound LLM call, falling back to mock", file=sys.stderr)
        return None
    if _USE_MOCK:
        return None
    if not _ALLOW_OUTBOUND or not _API_BASE.startswith("https://") or _API_BASE.split("://", 1)[1].split("/")[0] not in _ALLOWED_HOSTS:
        print(f"[LLM] real call blocked (outbound not allowed or host not in allowlist): {_API_BASE}", file=sys.stderr)
        return None
    _LLM_CALL_COUNT += 1
    url = f"{_API_BASE}/chat/completions"
    payload = {
        "model": _API_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {_API_KEY}",
        },
        method="POST",
    )
    try:
        print(f"[LLM] call #{_LLM_CALL_COUNT} to {_API_BASE} model={_API_MODEL}", file=sys.stderr)
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        content = body["choices"][0]["message"]["content"] or ""
        if not content.strip():
            print(f"[LLM] call #{_LLM_CALL_COUNT} returned empty content", file=sys.stderr)
            return None
        print(f"[LLM] call #{_LLM_CALL_COUNT} succeeded ({len(content)} chars)", file=sys.stderr)
        return content
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError,
            KeyError, OSError) as exc:
        print(f"[LLM] call #{_LLM_CALL_COUNT} failed: {exc}", file=sys.stderr)
        return None


def _parse_json_block(text):
    """Extract a JSON object from LLM output (handles markdown fences)."""
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.DOTALL)
    if m:
        text = m.group(1)
    else:
        m = re.search(r"(\{.*\})", text, flags=re.DOTALL)
        if m:
            text = m.group(1)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


def analyze(sanitized_text, evidence):
    """LLM analysis: returns a dict with predicted_trigger, predicted_payload,
    threatened_asset, confidence, suspicious_regions, llm_used."""
    if _USE_MOCK:
        return {
            "suspicious_regions": ["output result mux selects key under trigger"],
            "predicted_trigger": "constant plaintext comparison",
            "predicted_payload": "key dumped on output instead of ciphertext",
            "threatened_asset": "aes_key",
            "confidence": 0.9,
            "llm_used": False,
            "llm_source": "mock",
        }

    system_prompt = (
        "You are a hardware security analyst. Given sanitized Verilog RTL "
        "and static evidence (modules, output muxes, constant comparisons, "
        "IFT fan-in cones), predict the Trojan trigger class, payload class, "
        "threatened asset, and confidence (0-1). Respond ONLY with a JSON "
        "object: {\"predicted_trigger\": \"...\", \"predicted_payload\": \"...\", "
        "\"threatened_asset\": \"...\", \"confidence\": 0.0, "
        "\"suspicious_regions\": [\"...\"]}."
    )
    evidence_summary = {
        "modules": evidence.get("modules", []) if isinstance(evidence, dict) else [],
        "output_muxes": evidence.get("output_muxes", []) if isinstance(evidence, dict) else [],
        "constant_comparisons": evidence.get("constant_comparisons", []) if isinstance(evidence, dict) else [],
        "ift_trigger_candidates": evidence.get("ift", {}).get("trigger_candidates", []) if isinstance(evidence, dict) else [],
    }
    user_prompt = (
        "SANITIZED RTL:\n" + sanitized_text[:6000] +
        "\n\nSTATIC EVIDENCE:\n" + json.dumps(evidence_summary, indent=2)[:4000]
    )
    content = _chat(system_prompt, user_prompt)
    if content is None:
        print("[LLM] real backend call failed, falling back to mock", file=sys.stderr)
        return {
            "suspicious_regions": ["output result mux selects key under trigger"],
            "predicted_trigger": "constant plaintext comparison",
            "predicted_payload": "key dumped on output instead of ciphertext",
            "threatened_asset": "aes_key",
            "confidence": 0.9,
            "llm_used": False,
            "llm_source": "mock",
        }
    print(f"[LLM] real backend responded ({len(content)} chars)", file=sys.stderr)
    parsed = _parse_json_block(content)
    ok = (
        isinstance(parsed, dict)
        and isinstance(parsed.get("confidence"), (int, float))
        and isinstance(parsed.get("predicted_trigger"), str)
        and isinstance(parsed.get("predicted_payload"), str)
        and isinstance(parsed.get("threatened_asset"), str)
        and isinstance(parsed.get("suspicious_regions"), list)
        and all(isinstance(r, str) for r in parsed.get("suspicious_regions", []))
    )
    if not ok:
        print("[LLM] schema validation failed, falling back to mock", file=sys.stderr)
        return {
            "suspicious_regions": ["output result mux selects key under trigger"],
            "predicted_trigger": "constant plaintext comparison",
            "predicted_payload": "key dumped on output instead of ciphertext",
            "threatened_asset": "aes_key",
            "confidence": 0.9,
            "llm_used": False,
            "llm_source": "mock",
        }
    return {
        "predicted_trigger": parsed.get("predicted_trigger", "unknown"),
        "predicted_payload": parsed.get("predicted_payload", "unknown"),
        "threatened_asset": parsed.get("threatened_asset", "unknown"),
        "confidence": float(parsed.get("confidence", 0.5)),
        "suspicious_regions": parsed.get("suspicious_regions", []),
        "llm_used": True,
        "llm_source": "real",
        "model": _API_MODEL,
    }


def patch(analysis, sanitized_text):
    """LLM patch hook: given analysis + sanitized RTL, return patched RTL.
    Mock returns text unchanged (heuristic neutralization done in s3_generate).
    Real LLM rewrites based on analysis."""
    if _USE_MOCK:
        return sanitized_text
    system_prompt = (
        "You are a hardware security engineer. Given sanitized Verilog RTL "
        "containing a Trojan output mux or FSM DoS, produce a neutralized "
        "RTL that removes the Trojan payload while preserving correct "
        "functionality. Respond ONLY with the full patched Verilog code, "
        "no markdown fences."
    )
    user_prompt = (
        "ANALYSIS:\n" + json.dumps(analysis, indent=2) +
        "\n\nSANITIZED RTL:\n" + sanitized_text[:8000]
    )
    content = _chat(system_prompt, user_prompt, max_tokens=4096)
    if content is None or not content.strip():
        return sanitized_text
    return content


def property_sva(analysis):
    """Mock LLM SVA property generator: emits per-trigger assertions from IFT
    candidates when available, falling back to a generic key-leak assertion."""
    candidates = analysis.get("ift_trigger_candidates", []) if isinstance(analysis, dict) else []
    lines = [
        "/// Mock LLM-generated SVA (replace with real LLM call).",
        "/// Derived from IFT trigger candidates when available.",
        "",
    ]
    seen = set()
    for cand in candidates:
        cond = cand.get("condition", "")
        if cond in seen:
            continue
        seen.add(cond)
        lines.append(f"assert property (!( {cond} |-> result === key[127:0] ));")
    if not seen:
        lines.append("assert property (!(result === key[127:0]));")
    lines.append("")
    return "\n".join(lines)


def refine(error_text, previous_patch):
    """Mock LLM refine: if the S4 error indicates a payload leak or a compile
    error caused by leftover Trojan wires, neutralize the output mux by
    re-pointing result to muxed_new_block and dropping the trojan trigger/
    result wires. Otherwise returns the previous patch unchanged."""
    text = previous_patch
    err = (error_text or "").lower()
    trojan_keywords = ("evil", "trojan", "sanitize_result_b", "result_maybe_evil")
    needs_refine = any(k in err for k in (
        "trojan payload", "payload appeared", "dos", "ready stuck",
        "fail", "verdict: fail", "not defined", "unable to bind",
        "elaboration", "compile",
    ))
    if needs_refine and any(k in text.lower() for k in trojan_keywords):
        import re
        # Neutralize any assign result = <trojan_var>;
        text = re.sub(
            r"assign\s+result\s*=\s*(\w+)\s*;",
            lambda m: "assign result = muxed_new_block;"
            if any(k in m.group(1).lower() for k in trojan_keywords)
            else m.group(0),
            text)
        # Drop trojan trigger and result wires/assigns for any keyword variant.
        for kw in trojan_keywords:
            text = re.sub(
                rf"assign\s+{kw}\w*\s*=.*?;", "", text, flags=re.DOTALL)
            text = re.sub(
                rf"\s*wire\s+{kw}\w*\s*;\s*", "", text)
        text = text.replace("beginend", "end").replace("beginbegin", "begin")
    return text


def _load_yaml(text):
    try:
        return yaml.safe_load(text) or {}
    except Exception:
        return {}
