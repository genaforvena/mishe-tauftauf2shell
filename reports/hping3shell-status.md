# hping3shell — status

Admitted 2026-11-24 19:5xZ under standing approval #6 as the 134th engine
route. Claim: `CVE-2026-136131` (VulnCheck CNA 2026-11-24), CWE-787
out-of-bounds write, CVSS 4.0 6.0
`AV:N/AC:H/AT:P/PR:N/UI:P/VC:N/VI:L/VA:H/SC:N/SI:N/SA:N`. Affected hping
commits `7257579b` through master tip `3547c7691742c6eaa31f8402e0ccbb81387c1b99`;
no fixed version published. In the `IPOPT_RR` case of
`display_ipopt()`, the option pointer byte is clamped only to the packet's
option length, then reduced by `IPOPT_MINOFF`, and copied with `memcpy` into
`static char old_rr[40]`, so a reply declaring an RR length of up to 255 can
write up to 251 bytes past that global. Advisory reach through `hping3 -G`
and any RCE claim stay claims in this lab.

## Admission evidence

- Frontier brief `reports/frontier-hping3shell.md`; verbatim pinned source,
  fix patch and raw evidence in `lab/frontier/hping3shell/`
  (`PROVENANCE.md`, `pinned/`, `evidence/*.out`). `display_ipopt.c` sha256
  `e8ef2dd63b3f7b5e5d87d14a50bdc64c6befc94a8e21801f060708f2dcbb5e7b`,
  `waitpacket.c` sha256
  `f63e229c6d8708a23f29baeebb7e9d18dbefaa9a41db801c15866b07d52279e9`,
  `hping2.h` sha256
  `d3fa609e10355ca1ec2398b6ec9c670ff11574076795e86115ad0e4711699072`, fix
  patch sha256
  `23bb8db3b3d2ee241d355ce1af7c643ae1dc831ae6058c52fbdd2f806f400c92`,
  all recomputed by the harness on every replay.
- Operator verification 19:5xZ: `cd lab/frontier/hping3shell && sh run.sh`
  gave `PASS=12 FAIL=0`, rc 0. ASan reports `global-buffer-overflow` with
  `WRITE of size 68` (pointer `0x48`) and 86 (`0x5a`) 0 bytes after the
  40-byte `old_rr` at `standin/display_ipopt.c:112`. `nm -n plain/harness`
  places `old_rrlen.1@0x4040`, `old_rr.0@0x4060` and `canary@0x40a0`, so
  the measured gap from `old_rr.0` is 64. Packet-derived bytes
  `4f 4d 49 53` ("OMIS") land at canary[0..3] for `0x48`, and "OMISHE-OO" ×2
  plus "OMIS" at canary[0..21] for `0x5a`, each matching the derived packet
  offset. Fixed-source attack, safe (`i=4`), safe-zero (`i=0`) and plain-safe
  controls are clean. Frontier's clean `git archive 7ec6a3bd` replay is
  recorded in commit `34c3c573`.
- Frontier's live two-pane window 142 (`hping3shell`) was adopted without
  duplication (registry entries present, seed wall in place). Charter
  written; hy4-flash route 133→134, both resolver keys 267→269, wake-failure
  signal registration via the exact full-flag sync at pin
  `0d686bbad55c849e88334da64efff9da88ad528a`; pinned full-flag doctor as
  recorded in the operator wall. Witness W207 (#3822) returned ESTABLISHED
  AS LABELED at this pinned-function scope; no grade change, no r5.

## Wire stage (2026-11-24 20:3xZ, author-side)

- Real tree: `provision/hping-src` (HEAD `3547c769`, `display_ipopt.c`
  `e8ef2dd6…dcbb5e7b`) copied to `wire/hping-src`, configured `--no-tcl` and
  built with `-fsanitize=address -fcommon` plus an empty `compat/net/bpf.h`
  stub (BSD-only header, its use is `#if`-guarded off on Linux). No pinned
  source was hand-edited. The fixed tree is the same build with
  `pinned/fix.patch` applied (patched sha256
  `70f0112d12c52d8661736de85e1a5155ba717ca63b09b471cb7aaa7f0ba846c7`).
- Input: `hping3 -D -1 -G -I lo -c 3 -i 1 127.0.0.2` under `sudo -n`, PID
  captured from a wrapper shell; a second loopback socket sends an ICMP echo
  reply from 127.0.0.2 to 127.0.0.1 with IHL=15, RR option bytes
  `07 ff 48`, `OMIS` padding and a 64-byte `OMIS` payload. The echo id is
  packed in host byte order (x86 little-endian) to match hping's
  `getpid() & 0xffff` check.
- `cd lab/frontier/hping3shell/wire && sh run-wire.sh`: **9 PASS / 0 FAIL,
  rc 0**, reproduced from a clean copy of the lab. Pointer `0x48` aborts the
  live process with ASan `global-buffer-overflow`, `WRITE of size 68`, frame
  `display_ipopt wire/hping-src/display_ipopt.c:112`, 0 bytes after the
  40-byte `old_rr`; pointer `0x5a` gives `WRITE of size 86` at the same
  frame; the attack is deterministic on repeat. Valid RR (`rr_len=39`,
  pointer `8`) and the same attack against the patched real build both exit
  0 with no ASan error and print the RR from the injected packet.
- The kernel answers the malformed option with ICMP parameter-problem, but
  pcap still delivers the original packet to the live hping3 process. Raw
  output: `wire/evidence/wire-{attack,attack2,repeat,valid-rr,fixed-attack}.out`.
- Limits: ASan detection only in the real binary; chosen bytes at chosen
  offsets are still observed only in the plain stand-in harness. No pointer,
  IP or command control, no stock-glibc outcome, no r5. W207 witnessed only
  the earlier pinned-function stage; this wire stage awaits independent
  replay.

## Plain real build: chosen bytes at chosen offsets in an adjacent live global (W2, 20:5xZ, author-side)

`wire/plain-proof.sh` builds the same pinned tree **without** ASan
(`-O0 -g -fcommon`, `--no-tcl`), launches a real
`hping3 -D -1 -G -I lo -c 20 -i 1 127.0.0.2` under `sudo -n`, and injects
three loopback ICMP replies whose 40-byte RR option carries a unique,
non-periodic 36-byte marker (`0xa0…0xbb`) and whose ICMP payload carries a
unique 64-byte marker (`0x01…0x40`), with `rr_len=255`, `ptr=0xff` (so
`i = 251`). It then attaches GDB, computes the PIE base from
`/proc/$pid/maps`, dumps 120 bytes at `old_rr`, and `check_plain.py` verifies
the offsets. `wire/run-wire.sh` is unchanged.

- `nm -n -S plain-src/hping3` places `old_rr.0@0x29dc0` (40 bytes) and the
  adjacent real global `rc4_sbox@0x29e00` (256 bytes), i.e. `old_rr+0x40`.
  GDB independently labels the dumped line at `old_rr+64` as `<rc4_sbox>` in
  the live process.
- Attack: **4 PASS / 0 FAIL, rc 0**. `old_rr[46..109]` equals the unique
  payload bytes `0x01…0x40`; `rc4_sbox[0..45]` equals payload bytes
  18..63 (`0x13…0x40`) — attacker-chosen bytes at attacker-chosen offsets in
  a named adjacent global of the real plain build. Evidence:
  `wire/evidence/plain-attack-{gdb,proof}.out`.
- Baseline (`NO_INJECT=1`, no crafted frames): **3 PASS / 0 FAIL, rc 0**;
  `rc4_sbox[0..45]` is all zero. Evidence:
  `wire/evidence/plain-baseline-{gdb,proof}.out`.
- Preserved nuance: the shallow `old_rr[0..45]` are subsequently rewritten by
  kernel-generated parameter-problem RR replies (`i<=11`); the deeper chosen
  bytes persist because those later writes are shorter. The 251-byte copy
  reaches `rc4_sbox[0..185]`; only the first 46 bytes are asserted because
  those are the ones carrying our unique marker. No pointer, IP or command
  control, no r5; witness replay of this stage is UNKNOWN.
- Clean-copy replay: `git archive HEAD lab/frontier/hping3shell` extracted to
  `/tmp/w2-hping-clean` plus a copy of the gitignored `provision/` tree, then
  `sh plain-proof.sh` and `NO_INJECT=1 sh plain-proof.sh` from its `wire/`
  directory, gave 4 PASS and 3 PASS respectively, rc 0. The script rebuilt
  `plain-src/` from the provisioning tree; no pinned source was hand-edited.
- Patched-build control (`plain-fixed-proof.sh`, same crafted RR replies
  against the locally patched real tree, patched source sha256
  `70f0112d…b471cb7aaa7f0ba846c7`): **3 PASS / 0 FAIL**; `rc4_sbox[0..45]`
  stays all zero, so the chosen bytes are attributable to the unclamped
  `memcpy`. Evidence: `wire/evidence/plain-fixed-{gdb,proof,run}.out`.
- Ceiling measurement: `nm -n -S plain-src/hping3` filtered to the 251-byte
  write span `0x29dc0..0x29ebb` contains exactly two objects — `old_rr.0`
  and `random.c`'s `rc4_sbox`. No function pointer, GOT slot or control-flow
  object is reachable; overwriting the sbox would change PRNG output, not
  execution. This path offers no measured route to r5.

## Optimized (-O2) build: fortified consumer aborts before the write (W8, 2026-11-25 03:49Z, author-side)

One bounded experiment tested whether the 251-byte span could reach more
valuable globals when the pinned tree is compiled with optimization. It did
not: on this host the optimized build's consumer detects the overflow first.
This is a build-dependent negative, not a grade change.

- Rebuilt the unmodified pinned tree (`display_ipopt.c` sha256
  `e8ef2dd6…dcbb5e7b`) with GCC 13.3.0 and
  `CCOPT='-O2 -g -fcommon -Wall -Wno-unused -I../compat'`. Ubuntu's GCC
  defaults to `_FORTIFY_SOURCE 3` at `-O2` (`gcc -dM -E -O2 - </dev/null`
  shows it; `-O0` does not). `objdump -d` of `display_ipopt` shows
  `mov $0x28,%ecx` followed by `call __memcpy_chk@plt` at `0xa489` — the
  destination bound is the real 40-byte `old_rr`.
- `nm -n -S` layout in this `-O2` binary: `old_rr.0@0x24c00` (40 bytes),
  `j.0@0x24c40`, `i.1@0x24c44`, `rc4_seedflag@0x24c48`, `random.c`'s
  `rc4_sbox@0x24c60`. Unlike the `-O0` build, the 251-byte span would
  cover the RC4 indices here. That hypothetical was tested and negated:
  the write never completes.
- `wire/inject_rr_o2.py` sends three crafted loopback ICMP RR replies
  (`rr_len=255`, `ptr=0xff`, 205-byte payload) whose bytes 18..21 set
  `j=7`, 22..25 set `i=5`, 26..29 set `rc4_seedflag=1` and 50..204 set
  `sbox[0..154]=0x41`. `wire/o2-index-proof.sh` runs
  `hping3 -D -1 -G --rand-dest -I lo -c 24 -i 1 127.0.0.x` and reads
  `i/j/sbox` read-only at the `hp_rand` breakpoint.
- Vulnerable `-O2` attack: **3 PASS / 0 FAIL** — the live process ends with
  `*** buffer overflow detected ***: terminated`, GDB sees four states and
  no state with the crafted `i/j/fill`, so no global was overwritten. The
  same frame in the `-O0` build still performs the silent overwrite of W2/W6;
  the difference is the compiled consumer, not the packet.
- Controls: no-injection baseline **4 PASS / 0 FAIL** (23 GDB states, 24
  probe destinations, no abort); locally patched tree rebuilt at `-O2`
  (patched source sha256 `70f0112d…b471cb7aaa7f0ba846c7`) with the same
  injection **4 PASS / 0 FAIL** (20 states, 21 destinations, no abort).
  Raw evidence: `wire/evidence/o2-{attack,baseline,fixed}-*`.
- Ceiling preserved: this is a denial of service in the fortified build,
  not corruption, chosen-byte control or r5. It narrows the earlier
  "stock-glibc outcome UNKNOWN" only for this pinned source rebuilt with
  this host's GCC at `-O2`; an actual distribution `hping3` package build
  and other fortify settings remain UNKNOWN.
  A clean-archive replay from commit `90d635d6` (`git archive` plus the
  gitignored `provision/` tree, `wire/replay-o2.sh`) gave
  `STAGE OK baseline 4` / `attack 3` / `fixed 4`,
  `REPLAY_O2_OK: 11 checks`, rc 0. The first replay failed only on a runner
  tag collision (`NO_INJECT=1` overwrote `RUN_TAG`), fixed before that
  successful replay; author-side, witness verdict UNKNOWN.



## Clang rebuild: written RNG indices give deterministic chosen-byte control (W9, 2026-11-25 10:06Z, author-side)

A bounded layout probe closed the "other build" UNKNOWN without changing the
primitive. Rebuilding the same pinned source with clang 18 at `-O0 -g
-fcommon` changes `.bss` order: `nm` puts
`display_ipopt.old_rr@0x28f90` (40), then `hp_rand.i@+0x30`,
`hp_rand.j@+0x34`, `rc4_seedflag@+0x38`, `rc4_sbox@+0x40`. The same 251-byte
`memcpy` therefore reaches two more live globals, the RC4 indices `i` and
`j`, which gcc's layout places outside the span.

`wire/inject_rr_ij.py` writes `i0=0x20`, `j0=0x80`, `rc4_seedflag=1` and
`sbox[0..186]=0x00` from a crafted RR reply. Against a real clang-built
`hping3 -D -1 -G --rand-dest -I lo -c 24 -i 1 127.0.0.x` on loopback, GDB
read-only state showed `hp_rand.i=0x20` and `hp_rand.j=0x80` at the first
filled state (then `i` advancing by 4 per packet, `j` pinned at `0x80`), and
16/16 subsequent probe destination low bytes were `0x00`, the chosen byte.
The oracle predicted all 20 low bytes from logged live `i`/`j`/`sbox`; the
unattacked counterfactual was `0x3b`. Attack: 7 PASS / 0 FAIL. No-injection
baseline: 4 PASS / 0 FAIL (no filled state, zero chosen-byte destinations).
Locally patched clang build with the same frames: 4 PASS / 0 FAIL. All probes
stayed on `127.0.0.x` on `lo`; the raw socket sends 127.0.0.2 -> 127.0.0.1.

Scope: deterministic chosen-byte control in a **specific rebuild**, not the
gcc build of W2/W6 and not a distribution package. No full IP, pointer,
command or r5. Full 4-byte address control was deliberately not attempted:
an `x.x.x.x` probe would leave loopback. Witness verdict UNKNOWN.

## Current grade (2026-11-25 00:49Z)

Rungs 1-3 on the verbatim pinned upstream function under ASan. Rung 4 is
WIRE-VISIBLE and includes chosen bytes at chosen offsets in a named adjacent
global of the **real plain hping3 build**: a crafted loopback RR reply reaches
`display_ipopt()`; the ASan build aborts with `WRITE of size 68` / `86` past
`old_rr[40]`, and the plain build lets 251 attacker-chosen bytes land at
chosen offsets in `rc4_sbox` (GDB + zero baseline + patched control). W5
measured changed RNG output; W6 measures **attacker-chosen output** — all 187
reachable sbox bytes become a reply-chosen constant, and the chosen byte
dominates subsequent probe destinations (15/16 to 17/17 across measured
runs), with no debugger steering.
A valid RR reply and the locally patched build stay clean. Only the low byte
of `127.0.0.x` is controlled; no pointer, full-IP, command or rung 5. The
`-O2` rebuild on this host detects the copy in `__memcpy_chk` and aborts
before any write (W8). The clang `-O0` rebuild (W9) additionally reaches
`hp_rand.i`/`hp_rand.j`, giving 16/16 deterministic chosen-byte control in
that build; it is author-side and still only the low byte. An actual
distribution build and `IPOPT_LSRR` stay UNKNOWN. Witness replay:
pinned-function stage W207 ESTABLISHED; W6 W212 ESTABLISHED, both with no
grade change. The two wire stages (#3942), W5 (#3958) and W9 remain
author-side with verdicts UNKNOWN.


## Witness verdict (W207, #3822)

Independent replay from clean `git archive 34c3c573`: 12 PASS / 0 FAIL, rc 0,
all source-patch and fix-patch hashes exact. The witness reproduced ASan
`WRITE-68`/`WRITE-86` at pinned `standin/display_ipopt.c:112`, with clean
fixed-source, safe and safe-zero controls, and confirmed the plain-build
chosen bytes using its own independent non-periodic marker and a locally
built fixed binary. ESTABLISHED AS LABELED at the pinned-function scope: no
grade change, no real hping build, libpcap/raw socket, wire, pointer/IP,
command or r5. Its only NIT was wording: `old_rrlen.1` is at `0x4040`,
`old_rr.0` at `0x4060`; the 64-byte canary gap is correct. The symbol labels
are corrected above and in the README row; no measurement changed.

## One-command wire replay (W4, 2026-11-24 23:24Z)

`wire/replay-all-wire.sh` folds the two owed wire-stage asks (#3839 and
#3858) into one command. From a clean archive:

```
cd /home/mesh-home/mishe-tauftauf2shell &&
git archive HEAD lab/frontier/hping3shell | tar x -C /tmp/w4-hping &&
HPING_SRC=$PWD/lab/frontier/hping3shell/provision/hping-src \
  sh /tmp/w4-hping/lab/frontier/hping3shell/wire/replay-all-wire.sh
```

The driver rechecks the pinned `display_ipopt.c` sha256, copies the gitignored
provisioning tree into the archive, then runs the four stages in order and
asserts their exact pass counts. Author receipt at 23:24Z from that clean
archive: `STAGE OK asan 9`, `baseline 3`, `attack 4`, `fixed 3`,
`REPLAY_ALL_WIRE_OK: 19 checks`, rc 0. No new claim, no grade change; this is
a replay convenience, not independent acceptance.


## RNG behavior change from the overflow (W5, 2026-11-24 23:56Z)

`wire/rng-proof.sh` and `wire/check_rng.py` close the previous UNKNOWN: in a
real plain hping3 on loopback the crafted RR reply changes the next probe
destination chosen by `hp_rand()` from the overwritten `rc4_sbox`.

- Run mode: `hping3 -D -1 -G --rand-dest -I lo -c 16 -i 1 127.0.0.x`. All
  probes stay in 127.0.0.0/24 on `lo`; the local address stays 127.0.0.1 so
  the crafted reply passes the `waitpacket.c:94` destination check.
- GDB only reads state at `select_next_random_dest()` entry: static `i.1`,
  `j.0` and the 256 bytes of `random.c`'s `rc4_sbox`. No process state is
  written by the debugger. This build makes four `hp_rand()` calls per
  packet; the low byte of the probe destination is the first call's output.
- Baseline (`NO_INJECT=1`): **4 PASS / 0 FAIL**, 15 states / 16 destinations;
  every destination is predicted from the logged live sbox/i/j and no RR
  marker appears. Evidence `wire/evidence/rng-baseline-{gdb,run,proof}.out`.
- Attack: **6 PASS / 0 FAIL**, 12 states / 13 destinations, every
  destination predicted; state 4 carries `sbox[0..45]=0x13…0x40` from the
  crafted RR; the observed probe destination `127.0.0.79` matches the
  prediction from the overwritten sbox, while the unattacked counterfactual
  from the prior state is `127.0.0.179`. Evidence
  `wire/evidence/rng-attack-{gdb,run,proof}.out`.
- Ceiling at W5: no function pointer in the 251-byte span, no chosen-IP
  control without observing hidden i/j, no command, no rung 5. W6 below
  measures a chosen *byte* of output without debugger steering; full-IP
  control remains UNKNOWN. Author-side only; witness replay still owed.
- Negative preserved: the first attempt used `--rand-source`, but
  `waitpacket.c:94` checks the reply destination against `local.sin_addr`,
  which was randomized; no crafted frame reached `display_ipopt()` and the
  checker correctly reported `NO_TAINT`. The rand-dest mode fixed that.

Clean-archive replay 23:59Z from committed `35891e22`
(`git archive 35891e22 lab/frontier/hping3shell`, gitignored `provision/`
copied in, scripts built their own `plain-src`): baseline 4 PASS / 0 FAIL and
attack 6 PASS / 0 FAIL, rc 0 both. The concrete destination bytes differ
(`127.0.0.251` observed vs `127.0.0.226` counterfactual) because
`hp_rand_init()` seeds from `/dev/urandom`; the causal property and counts
are stable. No pinned source edited; all probes stayed in 127/8 on `lo`.

## Chosen RNG output byte (W6, 2026-11-25 00:49Z)

The W2 packet-to-global mapping (`rc4_sbox[n] == ICMP payload[18+n]`) and the
251-byte `memcpy` cap mean a crafted reply can set **all 187 reachable sbox
bytes**, not just the 46 bytes the W5 unique marker covered. A 205-byte
payload whose bytes 18..204 carry one chosen constant fills that whole span.
`wire/inject_rr_const.py` sends that reply (rr_len=255, ptr=0xff, 3 frames,
loopback 127.0.0.2→127.0.0.1); `wire/rngctl-proof.sh` runs the real plain
build with `--rand-dest 127.0.0.x` and reads RC4 state read-only in GDB;
`wire/check_rngctl.py` checks the observed probe destinations.

- `FILL=0x20`: **6 PASS / 0 FAIL, rc 0** — state 4 has `sbox[0..186]` filled
  with `0x20`, 16/16 in-tree post-attack destinations are `127.0.0.32` and
  the unattacked counterfactual is `127.0.0.70`; the final clean replay gave
  15/16 (one `0x10`).
- `FILL=0x40`: **6 PASS / 0 FAIL, rc 0** — same shape, 16/16 in-tree and
  17/17 clean-replay destinations `127.0.0.64`, counterfactual `127.0.0.132`.
  Two different chosen values show the byte is selected by the reply, not a
  stable PRNG run.
- Baseline (`NO_INJECT=1`): **4 PASS / 0 FAIL**; no filled state in 23 GDB
  samples. Patched-build control (`BIN=plain-fixed-src/hping3`, source sha256
  `70f0112d…b471cb7aaa7f0ba846c7`): **4 PASS / 0 FAIL**; the same crafted
  reply leaves the sbox unfilled, tying the effect to the unclamped memcpy.
- Stdout-only check: in-tree, the trailing runs of `0x20`/`0x40` are 16 probes
  long with no GDB involved, so GDB is observation/counterfactual only, never
  part of steering. Raw evidence: `wire/evidence/rngctl-*-{gdb,run,proof}.out`.
- Negative preserved: `-fno-common` (GCC 13 default) cannot link the pinned
  tree — `hping2.h:360` tentatively defines `delaytable` in every TU; see
  `wire/nocommon-negative.txt`. `-fcommon` is mandatory, not a harness choice.
  Two earlier injector assertion failures (28- and 32-byte RR option markers
  instead of 36) sent no frame and the checker correctly FAILed; fixed by
  using `bytes(range(0xA0, 0xA0 + 36))`.
- Ceiling: only the low byte of the probe destination is controllable; 69
  sbox bytes remain beyond the 251-byte reach and i/j are hidden. No pointer,
  command, shell or r5. Stock-glibc distribution build and `IPOPT_LSRR` stay
  UNKNOWN. W6 is now witness-established (W212, #4000); grade unchanged.

Two clean replays were run. The first (00:5xZ, `git archive HEAD`, the three
new scripts copied in) gave baseline 4 PASS, FILL=0x20 6 PASS, FILL=0x40
6 PASS, fixed control 4 PASS, rc 0, `CLEAN_REPLAY_W6_OK`, with plain/patched
source hashes exact and counterfactuals `127.0.0.140`/`127.0.0.156`. The final
one-command replay from committed `659f6eb0` (`wire/replay-rngctl.sh`, clean
archive, gitignored `provision/` copied in) gave `STAGE OK baseline 4`,
`STAGE OK fill32 6`, `STAGE OK fill64 6`, `STAGE OK fixed 4`,
`REPLAY_RNGCTL_OK: 20 checks`, rc 0; 15/16 fill32 and 17/17 fill64
destinations equalled the chosen byte. Counterfactuals vary with
`/dev/urandom` seeding. Preserved replay failures: a missing `/tmp` target
for `tar x`, stage-tag filename mismatches and a fixed-control assert path,
each fixed and re-verified from a fresh clean archive.

## Witness verdict (W212, #4000, 2026-11-25 01:39:54Z)

Witness replayed W6 from a clean `git archive 659f6eb0` into `/tmp/w212-w6`
(gitignored pinned source copied in) with the unmodified
`wire/replay-rngctl.sh`: `STAGE OK baseline 4`, `STAGE OK fill32 6`,
`STAGE OK fill64 6`, `STAGE OK fixed 4`, `REPLAY_RNGCTL_OK: 20 checks`,
rc 0 — **20 PASS / 0 FAIL**. Both `display_ipopt.c` digests were exact
(pinned `e8ef2dd6…dcbb5e7b`, patched `70f0112d…b471cb7aaa7f0ba846c7`);
the fix patch clamps `i` to `MAX_IPOPTLEN` and `hlen`. In the witness's own
plain build `nm` puts `old_rr.0@0x29dc0`, `rc4_sbox@0x29e00`, `i.1@0x29f04`,
`j.0@0x29f08`; the 251-byte span reaches `sbox[0..186]` but no `i`/`j` or
control-flow object. The injector sends a raw `127.0.0.2 -> 127.0.0.1` IP
frame on `lo`; the GDB breakpoint only prints and continues. Both fill
values filled `sbox[0..186]` and gave 16/16 chosen-byte destinations, with
counterfactuals `127.0.0.248` and `127.0.0.6`. Baseline and patched controls
had zero filled states, and `check_rngctl.py` predicts destinations from the
logged live RC4 state rather than echoing injected bytes. Verdict:
**ESTABLISHED AS LABELED**, no grade change, NO r5. Limits preserved:
probabilistic control (hidden `j` can index the 69 unreachable sbox bytes),
no full IP, pointer, command or r5; stock distro build and `IPOPT_LSRR`
remain UNKNOWN to the witness. Its only NIT was wording — the earlier
"OWED" lines about the W6 replay, now discharged here. Detail:
`.mishe-tauftauf/artifacts/witness-wall-w212-detail.md`. The witness's
still-owed list names #3942 (wire stages) and #3958 (W5).


## Next

Witness replay of the wire stages (#3942) and W5 (#3958) is still owed; W6
(#3975) was discharged by W212 above. The wire command in the earlier
section supersedes the old four-script request. W6's one-command replay is
kept below as a receipt, not an open ask:

```
cd /home/mesh-home/mishe-tauftauf2shell &&
git archive 659f6eb0 lab/frontier/hping3shell | tar x -C /tmp/w6-wit &&
cp -a lab/frontier/hping3shell/provision /tmp/w6-wit/lab/frontier/hping3shell/ &&
cd /tmp/w6-wit &&
HPING_SRC=$PWD/lab/frontier/hping3shell/provision/hping-src \
  sh lab/frontier/hping3shell/wire/replay-rngctl.sh
```

Expect `STAGE OK baseline 4`, `STAGE OK fill32 6`, `STAGE OK fill64 6`,
`STAGE OK fixed 4`, `REPLAY_RNGCTL_OK: 20 checks`, rc 0; this is exactly
what the witness observed. The driver rebuilds both trees from the
gitignored pinned source and applies the tracked fix patch itself. Two
preserved replay failures: a missing `/tmp/w6-wit` target for `tar x`, and
two stage-tag filename mismatches, both fixed in the committed scripts.
After the owed verdicts the only depth lane is a measured
attacker-controlled execution path; nothing observed supports r5.
