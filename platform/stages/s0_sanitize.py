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
import re

NEUTRAL_MAP = {
    "trojan_trig": "sanitize_cond_a",
    "result_maybe_evil": "sanitize_result_b",
}

# Keywords (matched case-insensitively) and markers that flag a comment as a
# Trojan hint worth stripping.
TROJAN_KEYWORDS = (
    "trojan", "trigger", "payload", "key leak", "key[127",
    "round_8_result", "evil", "skip mixcol", "debug port",
    "denial of service", "dos_triggered",
)
TROJAN_MARKERS = ("TROJAN BEGIN", "TROJAN END")


def _has_trojan_hint(snippet):
    low = snippet.lower()
    return any(kw in low for kw in TROJAN_KEYWORDS) or any(
        marker in snippet for marker in TROJAN_MARKERS
    )


def _sanitize_text(text):
    """Remove Trojan hint comments while preserving the line count.

    The text is scanned as a single stream so multi-line ``/* ... */`` block
    comments are removed as a unit. String literals are honoured so ``//`` or
    ``/*`` inside a quoted string are never treated as comments. Removed
    comment text is replaced by the same number of newlines it contained, so
    line numbers stay aligned for later position tracking.
    """
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        # String literal: honour quotes so comment markers inside strings are
        # not treated as comments.
        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if text[j] == '"':
                    break
                j += 1
            end = j + 1 if j < n else n
            out.append(text[i:end])
            i = end
            continue
        # Line comment: runs to end of line.
        if text[i : i + 2] == "//":
            j = text.find("\n", i)
            if j == -1:
                j = n
            if _has_trojan_hint(text[i:j]):
                i = j  # drop comment; the newline (if any) is copied next
            else:
                out.append(text[i:j])
                i = j
            continue
        # Block comment: runs to the first "*/", across multiple lines.
        if text[i : i + 2] == "/*":
            j = text.find("*/", i)
            if j == -1:
                j = n
            end = j + 2 if j < n else n
            comment = text[i:end]
            if _has_trojan_hint(comment):
                # Keep line count; separate tokens with a space when on one line
                # so ``wire/* hint */foo;`` does not become ``wirefoo;``.
                replacement = (
                    "\n" * comment.count("\n") if "\n" in comment else " "
                )
                out.append(replacement)
            else:
                out.append(comment)
            i = end
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _rename_identifiers(text):
    for orig, neutral in NEUTRAL_MAP.items():
        text = re.sub(r"\b" + re.escape(orig) + r"\b", neutral, text)
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
  /* Trojan trigger
   * leaks the key when evasion payload fires
   */
  assign result_maybe_evil = trojan_trig ? key : block;
  // ===== TROJAN END =====
  output wire [127:0] result
);
  // normal hint, kept
  assign result = block;
  wire h = "// not a comment";
endmodule
"""
    expected_neutral = "sanitize_cond_a"
    expected_result_neutral = "sanitize_result_b"
    cleaned = _sanitize_text(sample)

    assert sample.count("\n") == cleaned.count("\n"), "line count changed"
    assert "// TROJAN BEGIN" not in cleaned, "single-line trojan comment not removed"
    assert "/* Trojan trigger" not in cleaned, "multi-line block comment not removed"
    assert "leaks the key" not in cleaned, "block comment body not removed"
    assert "*/" not in cleaned or cleaned.count("*/") == 0, "block comment closer left behind"
    assert "normal hint, kept" in cleaned, "normal comment was removed"
    assert "wire trojan_trig" in cleaned, "code line with trojan_trig removed"
    assert 'wire h = "// not a comment";' in cleaned, "// inside string treated as comment"

    cleaned = _rename_identifiers(cleaned)
    assert expected_neutral in cleaned, "neutral name missing"
    assert expected_result_neutral in cleaned, "neutral result name missing"
    print("S0 self-check passed")
