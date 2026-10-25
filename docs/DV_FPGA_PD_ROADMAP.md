# AEGIS-AES: DV, Zynq-7000, and ASIC implementation roadmap

Status: proposed scope; none of the future milestones below are completed claims.

## Objective

Develop evidence for a DV internship first, then demonstrate the verified core on
Zynq-7000 and compare ASIC implementations of baseline AES and protected AES.
Reuse portable core RTL across targets. Keep board infrastructure and ASIC flow
configuration separate. FPGA timing results do not establish ASIC timing closure.

## Confirmed resources and remaining setup

- Board: Zynq-7000 ZC702 Evaluation Kit. AMD documents the production board
  device as XC7Z020-1CLG484C; confirm the actual board revision/part before build.
- Simulation: ModelSim available; QuestaSim installed with a license problem.
  User plans to restore QuestaSim for UVM, SVA, and functional coverage.
- Backend: user has access to Cadence tools through university. Exact tools,
  versions, license features, PDK, standard-cell libraries, and extraction/DRC/LVS
  support still require confirmation. Access to Cadence alone does not establish
  that every digital implementation/signoff product is available.
- Preferred implementation flow: Genus synthesis -> Innovus implementation ->
  Tempus STA, subject to university availability. Use the school's supported PDK
  and reference flow rather than selecting an unsupported technology.

Before depending on QuestaSim, run a small capability smoke test: UVM startup,
constrained randomization, one passing and one deliberately failing SVA property,
functional coverage sampling, and coverage database save/merge/report. Record
tool version and reproducible commands. Fixing startup alone is not proof that
all required features are licensed. ModelSim feature availability is edition-
and license-dependent and has not been established here.

While licensing is being repaired, proceed with M0, independent reference-vector
generation, existing-test regression, and verification-plan development. Never
silently skip unsupported assertions or coverage in the Questa acceptance run.

## Current evidence and gaps

- The design wraps an open-source secworks AES core configured for AES-128.
- Existing security tests cover CLEAN and five deliberately injected Trojan cases.
- `ground_truth.yaml` and generated configs define expected detectors.
- The security testbench does not yet enforce the detection-latency contract.
- `make all-cases` masks failures with `|| true`.
- Some vector aliases are checked out as files containing filenames. Test setup
  needs portable alias resolution before a fresh-checkout regression is reliable.
- Make targets reference missing `verif/sva`, `backend/openlane`, and `platform`
  content. Target names alone are not evidence of completed flows.
- The wrapper uses a hierarchical FSM tap. Replace it with an explicit port for
  portable synthesis and maintain one authoritative RTL source list.

## M0: specification and reproducible baseline

1. Define accepted key/block transactions, simultaneous input priority, requests
   while busy, reset interruption, output-valid timing, and recovery behavior.
   Do not assume a ready/valid interface: specify the existing interface first.
2. Define the threat model: attacker capabilities, trusted monitor inputs and
   checkpoints, output/debug exposure, and limits of the five Trojan examples.
3. For each security requirement define its trigger, observable response, maximum
   cycle delay, expected alarm bits, and reset exceptions.
4. Make one regression command propagate all failures and distinguish compile
   failure, runtime error, watchdog timeout, assertion failure, and data mismatch.
5. Record commit, source manifest, simulator/version, test, seed, and parameters.

Exit: a fresh checkout runs the baseline with machine-readable results and no
silently skipped tests. Do not silently regenerate or alter expected outputs.

## M1: self-checking verification environment

Build transaction generation, driver, passive monitor, scoreboard, reference
model, assertions, and coverage as separate components.

- Use an independent software AES reference for clean functional checking.
  Validate byte ordering with known-answer vectors. Do not derive the expected
  ciphertext from the same RTL datapath or checkpoint being checked.
- Track only accepted transactions. Handle reset-aborted work and key updates
  explicitly, and fail when expected results remain missing at end of test.
- Maintain separate functional and security predictions: an attack may require
  output suppression rather than a successful encryption response.
- Preserve existing directed tests; add reproducible constrained-random keys,
  blocks, transaction spacing, rekeying, and reset timing.
- Check accepted-versus-completed counts to detect dropped/duplicated outputs.

Use UVM if the available simulator supports the required class, randomization,
SVA, and coverage features. Otherwise first build the same component structure
with supported tools; document which features are unavailable. Add UVM agents,
sequences, analysis connections, and the scoreboard after establishing contracts.

Exit: mismatches and missing/extra outputs fail automatically; a recorded seed
reproduces a failure without manually examining a waveform.

## M2: security verification and coverage closure

- Unit-test KLG, FIC, RCM, RED, ORC, and TRU, then test their integration.
- Check legal FSM transitions, reset behavior, output gating, verdict timing,
  sticky alarms, bounded response, and persistence of lockdown until reset.
  Derive cycle bounds from the specification rather than assuming zero delay.
- FIC observes a binary-encoded FSM (0, 1, 2), despite one-hot terminology in
  comments. Assertions must check the actual encoding and allowed transitions.
- Exercise T01–T05, near-trigger inputs, clean random traffic, multi-alarm
  collisions, warning escalation, reset during attack, and attempted post-lockdown
  requests. Separate injection used for simulation from synthesizable board demos.
- Evaluate each monitor's blind spots. ORC's final-round recomputation alone is
  not an independent full-AES correctness oracle. Audit the provenance of the
  pre-final checkpoint and test corruption earlier in the datapath.
- Build requirement-to-test-to-checker-to-coverage traceability. Sample coverage
  from observed events. Include reachable state/transition, reset-phase,
  monitor/cause, attack-phase, warning escalation, and recovery bins.
- Merge regression coverage with explicit denominators and reviewed exclusions.
  Analyze code coverage separately; do not equate code coverage with requirements
  coverage. Prune unreachable cross-products rather than inflating test counts.
- Deliberately mutate selected behaviors to establish that checkers detect
  disabled alarms, corrupted ciphertext, and output-gating failures.

Exit: all mandatory requirements have executable checks and evidence; reachable
mandatory bins are hit or have documented waivers; all regression failures are
resolved or explicitly recorded. Report detection results only for the evaluated
attack set, with a defined trigger-to-alarm measurement and observation window.

## M3: Zynq-7000 implementation and demonstration

Target: ZC702 Evaluation Kit (XC7Z020 family). Confirm the installed board's exact
part/revision, Vivado and PS software tool versions, clock/reset configuration,
and board constraints before implementation. Start with a bare-metal PS test
application; Linux and DMA are optional later scope.

Recommended first integration: PS software -> AXI interconnect -> AXI4-Lite
register wrapper -> portable AEGIS core in PL. Begin with one clock domain and
polling. Add interrupts or DMA only when required by a measured use case.

- Define CONTROL, STATUS, key/input word registers, output registers, and alarm
  cause registers; specify atomic start, busy writes, byte strobes, read access,
  reset and zeroization. Do not expose a key readback register in the normal map.
- Verify AXI independently, including independent AW/W arrival, response stalls,
  invalid accesses, partial writes, and reset with transactions outstanding.
- Replay shared vectors through PS software and compare returned results with
  the independent software model. Keep core latency separate from PS/AXI latency.
- Capture clean operation, controlled attack activation, output suppression,
  alarm cause, lockdown, and recovery using host logs and ILA traces.
- Use separately identified clean and deliberately infected bitstreams, or a
  clearly bounded lab-only injection mechanism. Keep manifests and build labels.
- Define which PS/AXI copies of secrets are inside the zeroization claim; PL
  zeroization does not erase keys previously retained in PS memory or logs.

Exit: reproducible build/program/demo instructions, identified bitstream and
source revision, actual timing/resource reports, logs, and captured waveforms.
Physical demonstration supplements simulation and does not close coverage gaps.

## M4: ASIC backend and comparison

Preferred university flow: Cadence Genus -> Innovus -> Tempus, with the school's
supported libraries/PDK. Confirm these tools and required license features are
available. Identify Liberty timing libraries/corners, technology and cell LEF,
RC technology data, and layout/physical verification inputs required by that
flow. Confirm separate equivalence, extraction, DRC/LVS, or power-analysis tools
before including their results in completion criteria. Flow scripts cannot
replace missing technology inputs.

1. Freeze portable clean RTL; eliminate board/vendor dependencies and hierarchical
   synthesis taps; check reset mapping and synthesizability.
2. Define comparable tops: baseline AES versus protected AES with the same useful
   function and interface conditions. Keep Zynq PS and board infrastructure out.
3. Run synthesis, review constraints and timing, and perform equivalence checking
   where available; otherwise state the weaker gate-level validation performed.
4. Complete floorplan/PDN, placement, CTS, routing, extraction, and post-route STA.
5. Review setup/hold across supported corners, unconstrained paths, clock/reset
   assumptions, DRC/LVS results, and any unresolved violations.
6. Compare area, critical-path timing, latency, throughput, and power when valid
   activity data and tool support are available. Use identical libraries, corners,
   constraints, and comparable workloads; state assumptions and overhead formula.

Exit: scripts, technology/tool versions, layout, and timing/physical-check
summaries with limitations. A routed layout alone is not foundry signoff or proof
of tapeout readiness. FPGA PnR and ASIC physical design are separate results.

## CV evidence by milestone

- DV: verification plan, reusable environment, independent model, assertions,
  constrained-random regression, defined coverage closure, and debug examples.
- FPGA: AXI integration, identified board, repeatable demonstration, actual
  resource/timing data, and hardware traces.
- PD: selected technology, completed implementation stages, post-route STA,
  physical verification status, and fair baseline/security-overhead comparison.

Replace placeholders in CV bullets only after measurements exist. Keep planned
work separate from completed achievements. Prioritize M0–M2 for DV applications;
board and backend completion need not block using completed DV evidence.

## References

- AMD ZC702 board guide: https://docs.amd.com/api/khub/documents/V~m~5EUly0QvZEUAqEyKHQ/content
- Cadence digital implementation overview: https://www.cadence.com/en_US/home/tools/digital-design-and-signoff/soc-implementation-and-floorplanning/virtuoso-digital-implementation.html
