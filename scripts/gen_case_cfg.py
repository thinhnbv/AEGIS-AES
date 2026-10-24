#!/usr/bin/env python3
"""Generate the contract config for every infected case.

Each config file holds the expected detector mask, the expected latency,
whether the Trojan stays silent on clean NIST traffic, and the trigger
sequence file. The config is the single source of truth shared by the
Red team (the Trojan author) and the Blue team (the checker author).

Example (verif/cfg/T01_p1_key_dump.cfg):

[case]
case_id = T01_p1_key_dump
expected_mask = 0x01
expected_mask_bits = KLG
expected_latency = 1
expected_latency_cycles = 1
silent_under_nist = false
trigger_repeat = 1
trigger_seq = verif/vectors/trigger_T01.txt

Field notes
-----------
expected_mask
    Bitmask of the detectors that MUST fire, derived from
    detection.expected_checker. Bit positions come from
    rtl/aegis/aegis_defs.vh (KLG=0, FIC=1, RCM=2, RED=3, ORC=4).
    Extra detectors firing is allowed; only the listed ones are
    mandatory.

expected_latency_cycles
    detection.expected_latency as an integer when it is a plain
    number, otherwise -1 (the value is free-form prose such as
    "result-time" and cannot be checked mechanically).

silent_under_nist
    From verification.silent_under_nist. When true the Trojan must not
    disturb clean NIST traffic at all, so a monitor alarm on a NIST
    vector is a false positive and fails the regression. When false the
    case is allowed to be detectable on NIST traffic, so an alarm is
    reported but does not fail the regression.

trigger_repeat
    How many times the trigger vector must be sent before the case is
    considered detected. Defaults to 1. A detector that needs several
    consecutive results to build confidence (for example the KLG
    sliding-window byte-leak detector) requires this to be larger
    than 1, otherwise the security testbench would report a false
    negative even though the monitor works as specified.

A short alias config (T01.cfg -> T01_p1_key_dump.cfg) is written next to
the full-name config so a testbench can open verif/cfg/<CASE>.cfg for
both the full case id and the short form.
"""

import os

import yaml

BASE = "rtl/infected"
CFG_DIR = "verif/cfg"

# Detector name -> bit position in sec_status (see rtl/aegis/aegis_defs.vh).
MASK_MAP = {
    "KLG": 1 << 0,
    "FIC": 1 << 1,
    "RCM": 1 << 2,
    "RED": 1 << 3,
    "ORC": 1 << 4,
}


def parse_latency(value):
    """Return (raw_text, cycles) where cycles is an int or -1."""
    text = str(value).strip()
    try:
        return text, int(text)
    except ValueError:
        return text, -1


def write_cfg(path, case_id, mask, checker_list, latency_text, latency_cycles,
              silent, trigger_repeat, trigger_seq):
    with open(path, "w", encoding="utf-8") as fp:
        fp.write("[case]\n")
        fp.write(f"case_id = {case_id}\n")
        fp.write(f"expected_mask = {mask:02x}\n")
        fp.write(f"expected_mask_bits = {','.join(checker_list)}\n")
        fp.write(f"expected_latency = {latency_text}\n")
        fp.write(f"expected_latency_cycles = {latency_cycles}\n")
        fp.write(f"silent_under_nist = {'true' if silent else 'false'}\n")
        fp.write(f"trigger_repeat = {trigger_repeat}\n")
        fp.write(f"trigger_seq = {trigger_seq}\n")


def main():
    os.makedirs(CFG_DIR, exist_ok=True)

    for root, _dirs, files in os.walk(BASE):
        for name in sorted(files):
            if name != "ground_truth.yaml":
                continue

            gt_path = os.path.join(root, name)
            with open(gt_path, "r", encoding="utf-8") as fp:
                data = yaml.safe_load(fp)

            case_id = data.get("case_id") or os.path.basename(root)

            # detection.expected_checker is either "KLG" or a YAML list.
            checker = data.get("detection", {}).get("expected_checker", "")
            if isinstance(checker, str):
                checker_list = [c.strip() for c in checker.split(",") if c.strip()]
            else:
                checker_list = [str(c).strip() for c in (checker or [])]

            mask = 0
            for c in checker_list:
                mask |= MASK_MAP.get(c, 0)

            latency_text, latency_cycles = parse_latency(
                data.get("detection", {}).get("expected_latency", ""))

            # Both live under "verification" in the ground truth schema.
            verification = data.get("verification", {})
            silent = bool(verification.get("silent_under_nist", True))
            trigger_seq = verification.get("activation_seq", "")
            trigger_repeat = int(verification.get("trigger_repeat", 1))

            full_path = os.path.join(CFG_DIR, f"{case_id}.cfg")
            write_cfg(full_path, case_id, mask, checker_list, latency_text,
                      latency_cycles, silent, trigger_repeat, trigger_seq)
            print(f"Generated {full_path}")

            # Short alias, e.g. T01_p1_key_dump -> T01.
            short_id = case_id.split("_")[0]
            if short_id and short_id != case_id:
                short_path = os.path.join(CFG_DIR, f"{short_id}.cfg")
                write_cfg(short_path, case_id, mask, checker_list, latency_text,
                          latency_cycles, silent, trigger_repeat, trigger_seq)
                print(f"Generated {short_path}")

    print("All config files created.")


if __name__ == "__main__":
    main()
