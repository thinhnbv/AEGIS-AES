"""Simple information-flow tracking (IFT) for sanitized RTL.

Builds a signal dependency graph from `assign` statements and `if`
conditions in combinational always blocks, then computes the fan-in cone
of security-relevant sinks (result, ready, result_valid, dos_triggered)
back to primary inputs. Constant comparisons found inside a cone are
reported as possible Trojan triggers.

This is a lightweight, dependency-only IFT: it does not model bit-widths,
operator semantics, or sequential timing. It is good enough to surface
trigger candidates for the LLM analyzer (S2) to investigate further.
"""
import os
import re


def _find_files(src_dir):
    if not os.path.isdir(src_dir):
        return []
    return [os.path.join(src_dir, n)
            for n in sorted(os.listdir(src_dir)) if n.endswith(".v")]


_VERILOG_KEYWORDS = {
    "always", "assign", "begin", "end", "if", "else", "case", "casex", "casez",
    "default", "for", "while", "repeat", "forever", "initial", "final",
    "module", "endmodule", "input", "output", "inout", "wire", "reg", "integer",
    "real", "parameter", "localparam", "signed", "unsigned", "logic", "tri",
    "tri0", "tri1", "supply0", "supply1", "wand", "wor", "generate", "endgenerate",
    "function", "endfunction", "task", "endtask", "primitive", "endprimitive",
    "specify", "endspecify", "specparam", "include", "timescale", "default_nettype",
    "posedge", "negedge", "or", "and", "nand", "nor", "xor", "xnor", "not",
    "buf", "bufif0", "bufif1", "notif0", "notif1", "pullup", "pulldown",
    "rnmos", "rpmos", "nmos", "pmos", "cmos", "rcmos", "rfmos",
    "release", "event", "scancel", "scaletimes",
    "weak0", "weak1", "highz0", "highz1",
    "true", "false",
}


def _vars_in(expr):
    """Extract Verilog identifiers from an expression, excluding keywords and
    numeric/hex constants."""
    vars_ = set()
    for tok in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", expr):
        if tok in _VERILOG_KEYWORDS:
            continue
        if tok[0].isdigit():
            continue
        vars_.add(tok)
    return vars_


def _find_begin_end_blocks(text, anchor_re):
    """Yield the body of every `anchor ... begin ... end` block, respecting
    nested begin/end nesting so a block is not cut short by an inner `end`."""
    for m in anchor_re.finditer(text):
        start = m.end()
        # skip to the opening `begin`
        bm = re.search(r"\bbegin\b", text[start:])
        if not bm:
            continue
        body_start = start + bm.end()
        depth = 1
        i = body_start
        while i < len(text) and depth > 0:
            # find next begin or end at word boundary
            nb = re.search(r"\bbegin\b", text[i:])
            ne = re.search(r"\bend\b", text[i:])
            if nb and (not ne or nb.start() < ne.start()):
                depth += 1
                i += nb.end()
            elif ne:
                depth -= 1
                i += ne.end()
            else:
                break
        if depth == 0:
            yield text[body_start:i - len("end")]


def _strip_comments(text):
    text = re.sub(r"//[^\n]*", "", text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return text


def run_ift(sanitized_dir):
    files = _find_files(sanitized_dir)
    text = ""
    for f in files:
        with open(f, encoding="utf-8") as fp:
            text += "\n" + fp.read()
    text = _strip_comments(text)

    # target signal -> set of source signals it depends on
    deps = {}

    # --- assign statements -------------------------------------------------
    for m in re.finditer(r"assign\s+(\w+)\s*=\s*([^;]+);", text):
        target = m.group(1)
        expr = m.group(2)
        sources = _vars_in(expr) - {target}
        deps.setdefault(target, set()).update(sources)

    # --- always @* combinational blocks -----------------------------------
    # Over-approximation: every identifier used anywhere in the block may
    # affect every signal assigned in the block. This catches nested `if`
    # conditions that a single-regex scan would miss.
    comb_anchor = re.compile(r"always\s*@\*\s*", re.MULTILINE)
    for block in _find_begin_end_blocks(text, comb_anchor):
        used = _vars_in(block)
        assigned = set()
        for am in re.finditer(r"(\w+)\s*(<=|=)\s*", block):
            assigned.add(am.group(1))
        for av in assigned:
            deps.setdefault(av, set()).update(used - assigned)

    # --- sequential always blocks (posedge clk ...) -----------------------
    seq_anchor = re.compile(
        r"always\s*@\s*\((?:posedge|negedge)\s*\w+\s*(?:or\s*(?:posedge|negedge)\s*\w+\s*)*\)\s*",
        re.MULTILINE,
    )
    for block in _find_begin_end_blocks(text, seq_anchor):
        used = _vars_in(block)
        assigned = set()
        for am in re.finditer(r"(\w+)\s*<=\s*", block):
            assigned.add(am.group(1))
        for av in assigned:
            deps.setdefault(av, set()).update(used - assigned)

    # Sinks: security-relevant outputs / Trojan-payload carriers.
    sinks = ["result", "ready", "result_valid", "dos_triggered"]

    # Primary inputs: signals used as sources but never assigned as targets.
    all_targets = set(deps.keys())
    all_sources = set()
    for sset in deps.values():
        all_sources |= sset
    inputs = sorted(all_sources - all_targets)

    # Fan-in cone (reverse reachability) from each sink.
    def fan_in(sink):
        seen = set()
        stack = [sink]
        while stack:
            node = stack.pop()
            for src in deps.get(node, ()):
                if src not in seen:
                    seen.add(src)
                    stack.append(src)
        return seen

    cones = {}
    for s in sinks:
        cone = fan_in(s)
        if cone:
            cones[s] = sorted(cone)

    # Constant comparisons inside any sink's cone -> trigger candidates.
    hex_const = r"(128'h[0-9a-fA-F_]+|64'h[0-9a-fA-F_]+|32'h[0-9a-fA-F_]+|16'h[0-9a-fA-F_]+|8'h[0-9a-fA-F_]+)"
    trigger_candidates = []
    for m in re.finditer(r"(\w+)\s*(==|!=|>=|<=|>|<)\s*(" + hex_const + r")", text):
        lhs = m.group(1)
        const = m.group(3).replace("_", "")
        affects = [s for s, cone in cones.items() if lhs in cone]
        if affects:
            trigger_candidates.append({
                "condition": f"{lhs} {m.group(2)} {const}",
                "constant": const,
                "signal": lhs,
                "affects": affects,
            })

    return {
        "files": [os.path.basename(f) for f in files],
        "num_dependency_edges": sum(len(v) for v in deps.values()),
        "inputs": inputs,
        "sinks": sinks,
        "cones": cones,
        "trigger_candidates": trigger_candidates,
    }
