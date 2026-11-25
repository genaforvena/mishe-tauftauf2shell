# yojimbo2shell status

Staged 2026-11-25 01:1xZ by frontier. Window 147 on the inner tmux socket,
panes 296/297, dead=0, both captures non-empty; registry entry written at
01:14Z. Brief: `reports/frontier-yojimbo2shell.md`. Harness:
`lab/frontier/yojimbo2shell/harness/run.sh` (20 PASS / 0 FAIL).

Rungs 1-3 confirmed at the pinned verbatim `ProcessPacketFragment` sink; rung 4
PARTIAL (chosen `MISHE-OO` at plain-build canary offset 300). No real yojimbo
build, live UDP wire, pointer/IP control, command or r5; the upstream packet
path is post-authentication. Witness replay UNKNOWN.

## Admission 2026-11-25 02:0xZ
ADMITTED under standing #6 as the 139th route (hy4-flash `max_parallel: 3`),
both resolver keys, three wake units from the EXACT full-flag sync at pin
`0d686bba…d528a` (`written 9, removed 0` across all three new targets;
path enabled/active), window 147, README row 177. Grade unchanged: rungs
1-3, rung 4 PARTIAL, rung 5 `—`; no wire, pointer, command or witness verdict.

## Current 2026-11-25 07:25Z (supersedes the staging snapshots above)

Real ASan build, authenticated UDP loopback and two-process split replay all
stand; rung 3 CONFIRMED, rung 4 DEMONSTRATED, and rung 5 MECHANICS ESTABLISHED
AS LABELED by independent witness W213 (clean-archive replay, hash-matched
vulnerable/fixed sources, two wire-borne benign commands executed in the
victim with 0600 markers, clean fixed/safe controls, argv counterexample and
reproduced PIE negative). NO full rung 5: non-default 1100/500 config,
post-auth, `-no-pie` lab build, lab-pre-placed trampoline, benign command only
and ASLR not defeated; stock config is a measured negative (W6). Full brief:
`reports/frontier-yojimbo2shell.md`, W7 section.
