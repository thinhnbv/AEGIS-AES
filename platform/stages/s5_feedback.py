#!/usr/bin/env python3
"""Stage S5: Feedback refine on S4 failure.

If result.json overall = FAIL, send the error back to the LLM refine hook
and regenerate the patch. Tries at most 3 rounds. Writes each iteration
to build/<case>/iteration_N/ and updates <out>/verify/result.json with the
final verdict.
"""
import json
import os
import shutil

from platform.utils.llm_client import refine as llm_refine


def _load_result(out_dir):
    path = os.path.join(out_dir, "verify", "result.json")
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as fp:
            return json.load(fp)
    return {"verdict": "UNKNOWN"}


def run(case, out_dir, cfg):
    max_rounds = int(cfg.get("max_feedback_rounds", 3))
    result = _load_result(out_dir)

    round_no = 0
    while result.get("verdict") != "PASS" and round_no < max_rounds:
        round_no += 1
        iter_dir = os.path.join(out_dir, f"iteration_{round_no}")
        patched_dir = os.path.join(out_dir, "patched")

        # Re-run S3 into a fresh iteration dir (reuse the same patch source).
        if not os.path.isdir(patched_dir):
            print(f"S5 done: nothing to refine for {case} (no patched dir)")
            return

        # Copy previous patch into iteration dir as the refinement base.
        os.makedirs(iter_dir, exist_ok=True)
        if os.path.isdir(patched_dir):
            for name in os.listdir(patched_dir):
                if name.endswith((".v", ".sv")):
                    shutil.copy(os.path.join(patched_dir, name),
                                os.path.join(iter_dir, name))

        # Ask LLM refine hook (mock returns previous patch unchanged).
        error_text = "\n".join(result.get("errors", []))
        if not error_text and result.get("verdict") != "PASS":
            error_text = f"S4 verdict {result.get('verdict')}: verification failed"
        for name in list(os.listdir(iter_dir)):
            if not name.endswith(".v"):
                continue
            path = os.path.join(iter_dir, name)
            with open(path, encoding="utf-8") as fp:
                text = fp.read()
            text = llm_refine(error_text, text)
            with open(path, "w", encoding="utf-8") as fp:
                fp.write(text)

        # Copy refined files back into patched/ so the next S4 run uses them.
        if os.path.isdir(patched_dir):
            previous = {}
            for name in os.listdir(iter_dir):
                if not name.endswith((".v", ".sv")):
                    continue
                dst = os.path.join(patched_dir, name)
                previous[name] = (
                    open(dst, encoding="utf-8").read() if os.path.isfile(dst) else None
                )
                shutil.copy(os.path.join(iter_dir, name), dst)
            # If nothing changed, stop refining rather than looping.
            unchanged = True
            for name, prev_text in previous.items():
                with open(os.path.join(patched_dir, name), encoding="utf-8") as fp:
                    if fp.read() != prev_text:
                        unchanged = False
                        break
            if unchanged:
                print(f"S5: patch unchanged for {case}; stopping refine early.")
                break

        # Re-run S4 on the refined patch.
        from platform.stages import s4_verify as s4_mod
        s4_mod.run(case, out_dir, cfg)
        result = _load_result(out_dir)

    print(f"S5 done: {case} -> final verdict={result.get('verdict')} "
          f"after {round_no} refine round(s)")
