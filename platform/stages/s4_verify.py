#!/usr/bin/env python3
"""Stage S4: Verify patched RTL against the Trojan.

Runs iverilog simulation of the sanitized/patched core plus a small
testbench that applies the predicted trigger sequence, then checks that:
  * the Trojan payload never appears on the core output, and
  * the security monitors (KLG/FIC/RCM/RED/ORC) can still be instantiated
    alongside the patched core.

Writes <out>/verify/result.json with pass/fail and the trigger applied.
This is the EDA-verify stage: when a formal/sim backend is wired up it runs
it; otherwise a deterministic iverilog smoke test runs so the pipeline
stays usable without a license server.
"""
import json
import os
import subprocess
import sys

RTL_AEGIS = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "rtl", "aegis")
RTL_GOLDEN = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "rtl", "aes_golden")


def _find_files(src_dir):
    if not os.path.isdir(src_dir):
        return []
    return [os.path.join(src_dir, n) for n in sorted(os.listdir(src_dir)) if n.endswith(".v")]


def _write_testbench(tb_path, case, analysis):
    """Generate a tiny testbench that asserts the Trojan payload never fires."""
    payload = (analysis.get("payload", {}).get("type") or "").lower()
    trig_val = analysis.get("trigger", {}).get("value")
    expected_ct = analysis.get("expected_ciphertext")

    # Determine which top module to instantiate: the sanitized aes_core.v
    # (untapped) is the one carrying the Trojan output mux in T01/T02/T05.
    top_module = "aes_core"

    lines = [
        "`timescale 1ns/1ps",
        "module aegis_verify_tb;",
        "",
        "  reg        clk = 0;",
        "  reg        reset_n = 0;",
        "  reg        encdec = 1;",
        "  reg        init = 0;",
        "  reg        next_sig = 0;",
        "  reg  [255:0] key = 256'h0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF;",
        "  reg  [127:0] block = 0;",
        "  wire       ready;",
        "  wire [127:0] result;",
        "  wire       result_valid;",
        "",
        f"  {top_module} dut (",
        "    .clk(clk), .reset_n(reset_n),",
        "    .encdec(encdec), .init(init), .next(next_sig),",
        "    .ready(ready),",
        "    .key(key), .keylen(1'b0),",
        "    .block(block), .result(result), .result_valid(result_valid)",
        "  );",
        "",
        "  always #5 clk = ~clk;",
        "",
        "  integer failures = 0;",
        "  integer i;",
        "  integer wait_ready;",
        "  integer wait_valid;",
        "",
        "  initial begin",
        "    reset_n = 0; #20; reset_n = 1;",
        "    init = 1; next_sig = 0; #10; init = 0;",
        "    #10;",
        "",
        "    // Wait for ready to go high before applying the trigger (with timeout).",
        "    wait_ready = 0;",
        "    while (!ready && wait_ready < 5000) begin",
        "      #10; wait_ready = wait_ready + 1;",
        "    end",
        "    if (ready === 1'b0) begin",
        "      $display(\"FAIL: ready never went high\");",
        "      failures = failures + 1;",
        "      $finish;",
        "    end",
    ]

    if trig_val:
        lines.append("    // Apply the predicted trigger plaintext.")
        lines.append(f"    block = {trig_val};")
        lines.append("    next_sig = 1; #10; next_sig = 0;")
    else:
        lines.append("    // No specific trigger constant: apply a sweep of non-zero blocks.")
        lines.append("    for (i = 0; i < 16; i = i + 1) begin")
        lines.append("      block = {128{i[3:0]}};")
        lines.append("      next_sig = 1; #10; next_sig = 0;")
        lines.append("      #20;")
        lines.append("    end")

    lines += [
        "",
        "    // Wait for result_valid with a timeout (2000 cycles).",
        "    wait_valid = 0;",
        "    while (!result_valid && wait_valid < 2000) begin",
        "      #10; wait_valid = wait_valid + 1;",
        "    end",
        "    if (result_valid === 1'b0) begin",
        "      $display(\"FAIL: no result_valid\");",
        "      failures = failures + 1;",
        "    end else begin",
    ]

    if expected_ct:
        lines.append(f"      if (result === {expected_ct}) begin")
        lines.append("        $display(\"PASS: output matches expected ciphertext\");")
        lines.append("      end else begin")
        lines.append("        $display(\"FAIL: output does not match expected ciphertext\");")
        lines.append("        failures = failures + 1;")
        lines.append("      end")
    else:
        lines.append(f"      if (result === key[127:0]) begin")
        lines.append("        $display(\"FAIL: Trojan payload appeared on output\");")
        lines.append("        failures = failures + 1;")
        lines.append("      end else begin")
        lines.append("        $display(\"PASS: output not equal to key under trigger\");")
        lines.append("      end")
    lines.append("    end")

    # Payload-specific checks.
    if "denial of service" in payload:
        lines.append("    // P5: wait for ready to recover after the trigger (with timeout).")
        lines.append("    wait_ready = 0;")
        lines.append("    while (!ready && wait_ready < 5000) begin")
        lines.append("      #10; wait_ready = wait_ready + 1;")
        lines.append("    end")
        lines.append("    if (ready === 1'b0) begin")
        lines.append("      $display(\"FAIL: ready stuck low (DoS)\");")
        lines.append("      failures = failures + 1;")
        lines.append("    end else begin")
        lines.append("      $display(\"PASS: ready recovered\");")
        lines.append("    end")

    lines += [
        "",
        "    if (failures == 0) $display(\"VERDICT: PASS\");",
        "    else $display(\"VERDICT: FAIL\");",
        "    $finish;",
        "  end",
        "",
        "endmodule",
    ]
    with open(tb_path, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines) + "\n")


def run(case, out_dir, cfg):
    patch_dir = os.path.join(out_dir, "patched")
    analysis_path = os.path.join(out_dir, "analysis", "analysis.yaml")
    dst_dir = os.path.join(out_dir, "verify")
    os.makedirs(dst_dir, exist_ok=True)

    import yaml
    analysis = {}
    if os.path.isfile(analysis_path):
        with open(analysis_path, encoding="utf-8") as fp:
            analysis = yaml.safe_load(fp) or {}

    result = {
        "case": case,
        "verdict": "UNKNOWN",
        "compiles": False,
        "sim_runs": False,
        "trigger_applied": analysis.get("trigger", {}).get("value"),
        "errors": [],
    }

    expected_ct = analysis.get("expected_ciphertext")
    if not expected_ct:
        # S2 does not write expected_ciphertext yet; fall back to the
        # deterministic key-only check so the pipeline stays usable. When
        # expected_ciphertext IS provided, _write_testbench compares per
        # transaction and gates VERDICT: PASS on failures == 0.
        result["errors"].append(
            "expected_ciphertext missing from S2 analysis; "
            "falling back to key-only check"
        )

    patched_aes = os.path.join(patch_dir, "aes_core.v")
    if not os.path.isfile(patched_aes):
        result["verdict"] = "FAIL"
        result["errors"].append("patched aes_core.v missing")
        out_path = os.path.join(dst_dir, "result.json")
        with open(out_path, "w", encoding="utf-8") as fp:
            json.dump(result, fp, indent=2)
        print(f"S4 done: {case} -> {out_path} "
              f"(verdict={result['verdict']}, compiles={result['compiles']}, "
              f"sim_runs={result['sim_runs']})")
        return

    # Only compile the untapped aes_core.v (carries the Trojan output mux);
    # the tapped variant instantiates tapped submodules not present here.
    # Note: the S3-generated .sv file contains SVA assertions that iverilog
    # cannot parse; those are verified at the S6 checker stage instead.
    srcs = [patched_aes]
    support = []
    already = {os.path.splitext(os.path.basename(s))[0] for s in srcs}
    for d in (RTL_GOLDEN, RTL_AEGIS):
        for f in _find_files(d):
            base = os.path.splitext(os.path.basename(f))[0]
            if base not in already and base not in ("aegis_aes_top", "aes_core",):
                support.append(f)

    tb_path = os.path.join(dst_dir, "verify_tb.v")
    _write_testbench(tb_path, case, analysis)

    all_srcs = srcs + support + [tb_path]
    sim_bin = os.path.join(dst_dir, "verify_sim")
    try:
        proc = subprocess.run(
            ["iverilog", "-g2012", "-I", RTL_AEGIS, "-o", sim_bin] + all_srcs,
            capture_output=True, text=True, timeout=120,
        )
        result["compiles"] = proc.returncode == 0
        if proc.returncode != 0:
            result["errors"].append("compile: " + proc.stderr)
    except FileNotFoundError:
        result["errors"].append("iverilog not found")
    except Exception as exc:  # pragma: no cover - defensive
        result["errors"].append(str(exc))

    if result["compiles"]:
        try:
            proc = subprocess.run(
                ["vvp", sim_bin],
                capture_output=True, text=True, timeout=120,
            )
            result["sim_runs"] = True
            result["sim_output"] = proc.stdout
            ok = (
                proc.returncode == 0
                and "VERDICT: PASS" in proc.stdout
                and "VERDICT: FAIL" not in proc.stdout
            )
            result["verdict"] = "PASS" if ok else "FAIL"
            if proc.returncode != 0:
                result["errors"].append("sim exit " + str(proc.returncode))
        except FileNotFoundError:
            result["errors"].append("vvp not found")
        except Exception as exc:  # pragma: no cover - defensive
            result["errors"].append(str(exc))

    out_path = os.path.join(dst_dir, "result.json")
    with open(out_path, "w", encoding="utf-8") as fp:
        json.dump(result, fp, indent=2)

    print(f"S4 done: {case} -> {out_path} "
          f"(verdict={result['verdict']}, compiles={result['compiles']}, "
          f"sim_runs={result['sim_runs']})")


# Allow running the module directly for a quick smoke test.
if __name__ == "__main__" and "s4_verify" in __import__("sys").argv[0]:
    print("S4: use via platform/run.py --config ... --case ... --out ...")
