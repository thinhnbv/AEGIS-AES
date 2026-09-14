#!/usr/bin/env python3
"""
make_case.py - Tao khung benchmark Trojan moi

Usage:
    python scripts/make_case.py --id T02_p2_slow_leak --trigger T1 --payload P2 --author team
    python scripts/make_case.py --id T03_p3_skip_mixcol --trigger T4 --payload P3
    python scripts/make_case.py --id T05_p5_dos --author team  # mac dinh T1/P5

Duoc goi boi Makefile hoac chay truc tiep.
"""

import argparse
import os
import sys
from datetime import date

# =============================================================================
# Template ground_truth.yaml
# =============================================================================
GROUND_TRUTH_TEMPLATE = """\
case_id: {case_id}
base_design: aes_golden
author: {author}

trigger:
  class: {trigger_class}
  description: {trigger_desc}
  activation: "{trigger_activation}"
  rarity: "{trigger_rarity}"

payload:
  class: {payload_class}
  description: {payload_desc}
  asset: {payload_asset}
  observable: logic

location:
  file: aes_core.v
  module: aes_core
  line_start: TODO_FILL
  line_end: TODO_FILL
  always_block: null

detection:
  expected_checker: {expected_checker}
  expected_latency: {expected_latency}

verification:
  silent_under_nist: {silent_under_nist}
  activation_seq: verif/vectors/trigger_{case_short}.txt
"""

# =============================================================================
# Template trojan_patch.v
# =============================================================================
TROJAN_PATCH_TEMPLATE = """\
//======================================================================
//
// trojan_patch.v
// ----------------
// Trojan patch cho benchmark {case_id}.
//
// Trigger: {trigger_desc}
// Payload: {payload_desc}
//
// Chene vao aes_core.v tai vi tri sau:
//   assign ready = ready_reg;
//   // === TROJAN PATCH BEGIN ===
//   // === TROJAN PATCH END ===
//   assign result_valid = result_valid_reg;
//
//======================================================================

`default_nettype none

module trojan_{case_short}(
    input wire [127:0] block,
    input wire [255:0] key,
    input wire [127:0] muxed_new_block,
    output wire [127:0] result
);

    // --- Trigger ---
    // TODO: Dien trigger phu hop voi class {trigger_class}
    // Ví du T1: wire trojan_trig = (block == 128'h...);
    // Ví du T2: wire trojan_trig = (block[127:96] == key[143:112]);
    // Ví du T3: Dung bo dem ngoai, chan counting cycles
    // Ví du T4: FSM state-dependent
    wire trojan_trig;

    // --- Payload ---
    // TODO: Dien payload phu hop voi class {payload_class}
    // Ví du P1: result = key[255:128];
    // Ví du P2: result = key[255:128] ^ block;
    // Ví du P3: Round skipping logic
    // Ví du P4: Mo cong debug
    // Ví du P5: result = 128'd0; ready = 0;
    assign result = trojan_trig ? muxed_new_block : muxed_new_block;

endmodule

`default_nettype wire

//======================================================================
// EOF trojan_{case_short}.v
//======================================================================
"""

# =============================================================================
# Template README.md
# =============================================================================
README_TEMPLATE = """\
# {case_id}

## Mo ta

**Trigger**: {trigger_desc}
**Payload**: {payload_desc}
**Observable**: logic

## Ket qua kỳ vong

- NIST regression: {nist_result}
- KLG/FIC/RCM/ORC bat duoc: {expected_checker}
- Latency: {expected_latency} chu ky

## Activation

Can tao file `verif/vectors/trigger_{case_short}.txt` voi trigger tuong ung.

## Trang thai

- [ ] Viet logic Trojan vao aes_core.v
- [ ] Tao activation vector
- [ ] Kiem tra NIST van pass
- [ ] Chay make security, xac nhan bat duoc
- [ ] Cap nhat line_start/line_end trong ground_truth.yaml
"""

# =============================================================================
# Trigger/Payload metadata
# =============================================================================
TRIGGER_INFO = {
    "T1": {
        "class": "T1",
        "description": "Plaintext bang hang so 128-bit dinh truoc",
        "rarity": "2^-128",
        "example_activation": "128'hDEADBEEF_CAFEBABE_00000000_00000000",
    },
    "T2": {
        "class": "T2",
        "description": "Chuoi plaintext phu thuoc key",
        "rarity": "2^-64",
        "example_activation": "block[127:96] == key[143:112]",
    },
    "T3": {
        "class": "T3",
        "description": "Bo dem dat nguong chu ky",
        "rarity": "2^-16",
        "example_activation": "counter >= 16'hFFFF",
    },
    "T4": {
        "class": "T4",
        "description": "Trang thai FSM hiem gap",
        "rarity": "2^-10",
        "example_activation": "aes_core_ctrl_reg == 2'b11 && round_cnt == 4'd5",
    },
}

PAYLOAD_INFO = {
    "P1": {
        "class": "P1",
        "description": "Thay ciphertext bang khoa AES-128",
        "asset": "aes_key",
        "expected_checker": "KLG",
        "expected_latency": "1",
        "nist_result": "PASS (im lang)",
    },
    "P2": {
        "class": "P2",
        "description": "Ro ri 8 bit khoa vao ciphertext",
        "asset": "aes_key",
        "expected_checker": "KLG",
        "expected_latency": "1",
        "nist_result": "PASS (im lang)",
    },
    "P3": {
        "class": "P3",
        "description": "Bo qua buoc MixColumn/Skip round",
        "asset": "aes_correctness",
        "expected_checker": "ORC, RCM",
        "expected_latency": "1-10",
        "nist_result": "FAIL (sai ciphertext)",
    },
    "P4": {
        "class": "P4",
        "description": "Mo cong debug, xuat state noi bo",
        "asset": "aes_state",
        "expected_checker": "FIC, RED",
        "expected_latency": "1",
        "nist_result": "PASS hoac FAIL tuy trigger",
    },
    "P5": {
        "class": "P5",
        "description": "Giu busy va chan ket qua (DoS)",
        "asset": "aes_availability",
        "expected_checker": "RCM",
        "expected_latency": "TODO",
        "nist_result": "FAIL (timeout)",
    },
}


# =============================================================================
# Main
# =============================================================================
def parse_args():
    parser = argparse.ArgumentParser(
        description="Tao khung benchmark Trojan moi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Vi du:
  python scripts/make_case.py --id T02_p2_slow_leak --trigger T3 --payload P2
  python scripts/make_case.py --id T05_p5_dos --trigger T1 --payload P5 --author team
  python scripts/make_case.py --id T03 --trigger T4 --payload P3
        """,
    )
    parser.add_argument(
        "--id",
        required=True,
        help="Case ID, vd: T02_p2_slow_leak hoac T02",
    )
    parser.add_argument(
        "--trigger",
        default="T1",
        choices=["T1", "T2", "T3", "T4"],
        help="Trigger class (default: T1)",
    )
    parser.add_argument(
        "--payload",
        default="P5",
        choices=["P1", "P2", "P3", "P4", "P5"],
        help="Payload class (default: P5)",
    )
    parser.add_argument(
        "--author",
        default="team",
        choices=["team", "llm_redteam", "trusthub"],
        help="Author (default: team)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Normalize case_id
    case_id = args.id
    if not case_id.startswith("T"):
        case_id = "T" + case_id

    # Generate case_short (e.g., T02 from T02_p2_slow_leak)
    parts = case_id.split("_")
    case_short = parts[0]  # "T02_p2_slow_leak" -> "T02"

    # Build output path
    infected_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "rtl", "infected", case_id
    )

    # Check if already exists
    if os.path.exists(infected_dir):
        print(f"Loi: Thu muc da ton tai: {infected_dir}", file=sys.stderr)
        sys.exit(1)

    # Get metadata
    t_info = TRIGGER_INFO[args.trigger]
    p_info = PAYLOAD_INFO[args.payload]

    # Create directory
    os.makedirs(infected_dir, exist_ok=False)
    print(f"Tao thu muc: {infected_dir}")

    # --- ground_truth.yaml ---
    gt_content = GROUND_TRUTH_TEMPLATE.format(
        case_id=case_id,
        author=args.author,
        trigger_class=t_info["class"],
        trigger_desc=t_info["description"],
        trigger_activation=t_info["example_activation"],
        trigger_rarity=t_info["rarity"],
        payload_class=p_info["class"],
        payload_desc=p_info["description"],
        payload_asset=p_info["asset"],
        expected_checker=p_info["expected_checker"],
        expected_latency=p_info["expected_latency"],
        silent_under_nist=p_info["nist_result"] == "PASS (im lang)",
        case_short=case_short,
    )

    gt_path = os.path.join(infected_dir, "ground_truth.yaml")
    with open(gt_path, "w", encoding="utf-8") as f:
        f.write(gt_content)
    print(f"  + ground_truth.yaml")

    # --- trojan_patch.v ---
    patch_content = TROJAN_PATCH_TEMPLATE.format(
        case_id=case_id,
        case_short=case_short,
        trigger_class=args.trigger,
        trigger_desc=t_info["description"],
        payload_class=args.payload,
        payload_desc=p_info["description"],
    )

    patch_path = os.path.join(infected_dir, "trojan_patch.v")
    with open(patch_path, "w", encoding="utf-8") as f:
        f.write(patch_content)
    print(f"  + trojan_patch.v")

    # --- README.md ---
    readme_content = README_TEMPLATE.format(
        case_id=case_id,
        case_short=case_short,
        trigger_desc=t_info["description"],
        payload_desc=p_info["description"],
        expected_checker=p_info["expected_checker"],
        expected_latency=p_info["expected_latency"],
        nist_result=p_info["nist_result"],
    )

    readme_path = os.path.join(infected_dir, "README.md")
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(readme_content)
    print(f"  + README.md")

    # --- Instructions ---
    print()
    print("=" * 60)
    print(f"Tao xong khung cho {case_id}")
    print("=" * 60)
    print()
    print("Cac buoc tiep theo:")
    print(f"  1. Viet logic Trojan vao aes_core.v")
    print(f"  2. Copy thanh aes_core_tapped.v, doi module name thanh aes_core_tapped")
    print(f"  3. Them port: output wire [1407:0] round_keys_flat")
    print(f"  4. Doi: aes_key_mem -> aes_key_mem_tapped")
    print(f"  5. Tao verif/vectors/trigger_{case_short}.txt voi trigger activation")
    print(f"  6. Cap nhat line_start/line_end trong ground_truth.yaml")
    print()
    print("Sau do chay:")
    print(f"  make sim CASE={case_id}")
    print(f"  make security CASE={case_id}")


if __name__ == "__main__":
    main()
