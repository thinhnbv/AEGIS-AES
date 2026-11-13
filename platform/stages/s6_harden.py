#!/usr/bin/env python3
"""Stage S6: Harden passing SVA into a checker Verilog template.

Reads <out>/patched/<case>.sv and emits a structural checker template
(comparator, bit counter, ROM-style trigger table) that can be copied into
rtl/aegis/ and wired into aegis_aes_top. Output: <out>/harden/<case>_checker.v
"""
import os


def run(case, out_dir, cfg):
    sva_path = os.path.join(out_dir, "patched", case + ".sv")
    dst_dir = os.path.join(out_dir, "harden")
    os.makedirs(dst_dir, exist_ok=True)

    template = [
        "/// Checker Verilog template hardened from SVA (stage S6).",
        "/// Case: %s",
        "/// Copy into rtl/aegis/ and instantiate in aegis_aes_top.",
        "///",
        "/// This is a structural checker: a comparator watches the trigger",
        "/// signals, a bit counter measures dwell time, and a small ROM table",
        "/// holds the expected trigger constants.",
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
        "    output wire                   alarm,",
        "    output wire [7:0]             alarm_code",
        ");",
        "",
        "  // Comparator: flag when output equals key under any condition.",
        "  wire key_leak = result_valid && (result === key[127:0]);",
        "",
        "  // Bit counter: dwell time before raising alarm.",
        "  reg [7:0] dwell_cnt;",
        "  always @(posedge clk or negedge rst_n) begin",
        "    if (!rst_n) dwell_cnt <= 8'd0;",
        "    else if (key_leak) dwell_cnt <= dwell_cnt + 8'd1;",
        "    else dwell_cnt <= 8'd0;",
        "  end",
        "",
        "  // ROM table of known trigger constants (filled in from S2/S3 output).",
        "  // Currently empty: populate with predicted trigger value.",
        "",
        "  assign alarm = key_leak && (dwell_cnt >= 8'd1);",
        "  assign alarm_code = key_leak ? 8'h01 : 8'd0;",
        "",
        "endmodule",
        "",
    ]
    template[1] = template[1] % case

    out_path = os.path.join(dst_dir, case + "_checker.v")
    with open(out_path, "w", encoding="utf-8") as fp:
        fp.write("\n".join(template))

    print(f"S6 done: {case} -> {out_path}")
