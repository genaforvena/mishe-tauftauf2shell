# Research methodology

Rung definitions and the evidence policy below are preserved from the former README evidence key. The [evidence ladder](assets/evidence-ladder.svg) graphic is generated from `research-manifest.json`.

## Evidence key

The rungs are depth of proof, not boxes to tick:

- **R1** suspected vulnerability — source or advisory reasoning, no trigger.
- **R2** reproducible crash — a deterministic input faults the lab process.
- **R3** confirmed memory corruption — ASan/UBSan/Valgrind/gdb observes bad
  memory state, not just a fault.
- **R4** demonstrated impact — chosen bytes, pointer control or a benign
  marker exercised in the lab build.
- **R5** working remote command execution — attacker-controlled wire or
  request input makes a live target run a lab-chosen benign command, with
  vulnerable, fixed and safe-input controls and an independent witness replay.
  Additive and per-build, never a relabel of a pointer fault or an in-process
  marker; [docs/rce.md](../docs/rce.md) is the acceptance contract. Twelve R5
  cells are witness-ESTABLISHED, each only under the build, oracle and
  configuration scope named in its row; author-only command claims stay
  UNKNOWN.

Rung cells: `✓` demonstrated · `◐` limited (harness-only, instrumented, or a
count-controlled effect) · `—` not demonstrated.

Top-rung tiers: **LIVE** = real process on loopback, with the request/wire path
reached; **CODE** = verbatim pinned upstream or library bytes, in-process;
**HARNESS** = extracted or synthetic harness only, no real consumer. A
**Witness W##** or **tape #N** marker means an independent replay was accepted
at the exact scope named in that row's boundary; no marker means no
independent replay at that scope. Author reports are never acceptance.

## Research protocol

Every experiment stays inside the laboratory: pinned source trees, local builds and loopback-only instances under `lab/`. A rung cell records the boundary actually reached, never the ceiling claimed by an advisory or by the researcher. Failed hypotheses, negative results and UNKNOWNs stay in the record; an author verdict is never acceptance. The witness replays claims from a clean checkout and names the exact build, configuration and oracle at which its verdict holds. See [AGENTS.md](../AGENTS.md) for the governing evidence discipline and [docs/rce.md](rce.md) for the rung-5 acceptance contract.
