#!/usr/bin/env python3
"""AEGIS-AES Red/Blue-team pipeline entry point.

Usage:
    python3 platform/run.py --config platform/config/one_shot.yaml \
        --case T01_p1_key_dump --out build/runs/20260101_000000_one_shot
"""
import argparse
import importlib
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

STAGE_MODULES = {
    "s0": "platform.stages.s0_sanitize",
    "s1": "platform.stages.s1_static",
    "s2": "platform.stages.s2_analyze",
    "s3": "platform.stages.s3_generate",
    "s4": "platform.stages.s4_verify",
    "s5": "platform.stages.s5_feedback",
    "s6": "platform.stages.s6_harden",
}


def load_config(path):
    import yaml
    with open(path, "r", encoding="utf-8") as fp:
        return yaml.safe_load(fp)


def main():
    parser = argparse.ArgumentParser(description="AEGIS-AES LLM pipeline")
    parser.add_argument("--config", required=True, help="path to YAML config")
    parser.add_argument("--case", required=True, help="infected case id")
    parser.add_argument("--out", required=True, help="output run directory")
    args = parser.parse_args()

    cfg = load_config(args.config)
    # Honor backend mode from config so S2/S3 never call an external API
    # when backend: static (llm_client reads this env var).
    backend = cfg.get("backend")
    if backend:
        os.environ["AEGIS_LLM_BACKEND"] = str(backend)

    case_dir = os.path.join("rtl", "infected", args.case)
    if not os.path.isdir(case_dir):
        print(f"ERROR: case directory not found: {case_dir}", file=sys.stderr)
        sys.exit(1)

    os.makedirs(args.out, exist_ok=True)

    stages = cfg.get("stages", ["s0"])
    s4_verdict = None
    for name in stages:
        mod_path = STAGE_MODULES.get(name)
        if mod_path is None:
            print(f"ERROR: unknown stage {name}", file=sys.stderr)
            sys.exit(1)
        mod = importlib.import_module(mod_path)
        if not hasattr(mod, "run"):
            print(f"ERROR: stage {name} has no run()", file=sys.stderr)
            sys.exit(1)
        mod.run(args.case, args.out, cfg)
        if name == "s4":
            res_path = os.path.join(args.out, "verify", "result.json")
            try:
                with open(res_path, encoding="utf-8") as fp:
                    s4_verdict = json.load(fp).get("verdict")
            except (FileNotFoundError, json.JSONDecodeError):
                s4_verdict = None

    if "s4" in stages and s4_verdict in ("FAIL", "UNKNOWN", None):
        print(f"ERROR: S4 verdict={s4_verdict}; pipeline failed", file=sys.stderr)
        sys.exit(1)

    print(f"Pipeline done: {args.out}")


if __name__ == "__main__":
    main()
