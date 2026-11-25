# Determinism receipt — W21 live shipped-3.20b chosen-pointer wire TERM (W23)

Time: 2026-11-25 10:46:51Z–10:47:45Z. One command from repo root:

```
bash lab/frontier/synchronet2shell/release-label/term320b/real320b/run-determinism.sh
```

The wrapper runs the **unmodified** W21 driver `run-real320b.sh` three times.
Each run rebuilds the identical pinned `db9c5d6f` tree, starts a fresh
loopback-only server on fresh per-PID ports, sends the 40-byte control first
and the 64-byte chosen TERM (41xA + 3xB + `MISHE-OOTAUFTAUF` + 4xZ) second,
then copies both server logs into this directory. No claim is changed; this
measures run-to-run stability of the chosen bytes and the teardown fault.

Result: **13 PASS / 0 FAIL**, rc 0. Each driver run printed
`RESULT: PASS=4 FAIL=0`. For all three runs the control probe was

```
REAL_320B_PROBE sizeof=41 l=40 off41=00 cv=00000000 first=(nil) last=(nil)
```

and the chosen probe was

```
REAL_320B_PROBE sizeof=41 l=64 off41=42 cv=4853494d first=0x465541544f4f2d45 last=0x5a5a5a5a46554154
```

followed by `Node 1 destructor begin` and no `destructor end`. After all
three runs `git -C src-tree/320b diff --quiet -- src/sbbs3/answer.cpp`
passed: the W21 driver restored the pinned source.

Normalizing away only the timestamp/prefix and keeping the probe payload plus
`destructor begin`, all three runs have the same sha256:

```
291d85a5beef73d415858d77bcad41f0d1f8552510c39771ba09a64705da5559
```

Files: `run-{1,2,3}.log` (driver output), `run-{1,2,3}-control40.log`,
`run-{1,2,3}-vuln.log` (server transcripts). Server logs retain their own
timestamps, ports and PIDs; those are artifacts, not normalized invariants.

Ceiling unchanged: three live shipped-release observations of chosen bytes in
adjacent `sbbs_t` fields and a teardown fault, over a loopback SSH wire. No
chosen instruction pointer, command, measured DoS rate, ASLR defeat or r5.
Author replay, not a witness verdict.
