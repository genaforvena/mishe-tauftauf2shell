# gdbserver2shell — status

Admitted 2026-11-23 ~01:0xZ under standing approval #6 as the 94th engine
route. Frontier staged this lane at 01:01Z with a brief
(`reports/frontier-gdbserver2shell.md`), site charter, seed wall, hash-pinned
upstream source plus a derived fixed snapshot, and a two-pane inner tmux window
(index 99, created 01:03Z). A stale 2026-11-21 held-proposal window at index 23
had the same name and was still live; frontier's duplicate check missed it. The
fresh index-99 window was adopted and the stale one retired at admission, with
the registry corrected to 99 entries / 99 unique names. Admission added the
hy4-flash `max_parallel: 3` route and the path, debounce and `@gdbserver2shell`
slice drop-in from the exact full-flag sync (pin
`0d686bbad55c849e88334da64efff9da88ad528a`; `written 3, removed 0`), followed
by `systemctl --user daemon-reload`; the path unit is enabled and active. Both
`m2shell-wake@gdbserver2shell.service` and `m2shell-wake-gdbserver2shell.path`
were added to the site's owner resolver map so future failures address
`operator`, not the dead `genome` fallback. Admission changes no grade.

- Claim: CVE-2026-121997 / GHSA-jq36-9pw3-8r4v (Red Hat, 2026-11-05, HIGH 8.1,
  `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`, CWE-122). Upstream HEAD
  `633ae02c4ea8f87c670f7192804349860cfa291d`, fetched 2026-11-23, is **still
  vulnerable**; the fix is Andrew Burgess's 2026-11-16 gdb-patches `[PATCH 2/5]`
  (posted, not merged), so there is no tagged fixed release and no upstream
  numeric version range. The "fixed" snapshot is the pinned file with the
  adapted patch applied, not a vendor release. Pins: vulnerable
  `tracepoint-633ae02.cc` SHA-256
  `942306a5b1f96693a64d18819973e7e306faa1481f373615487a5fd2b4df4e2e`, fixed
  `tracepoint-fixed.cc` `c3aa8ac26253ff3fa79d6dd9caa13ae09c5c6471cf3499b22fa5b0926af95f17`,
  fix patch `5b8bc3cb235eb2ced96da42b15c66ec7f2510deace6f5a943b7e567e8a67d43f`;
  full provenance in `lab/frontier/gdbserver2shell/PROVENANCE.md`. The advisory's
  `process_info_private::thread_db` overwrite and `qGetTLSAddr` RIP chain are
  claims, not lab observations.
- Primitive: in the verbatim pinned `cmd_qtdpsrc()`, `unpack_varlen_hex` reads
  `SLEN` from the RSP packet (RSP numbers are hex) and `xmalloc(slen+1)`
  allocates from that declared length, but `hex2bin(packet, src, strlen(packet)/2)`
  writes the actual decoded BYTES length. With `SLEN=1` and N decoded bytes the
  result is an N-2 byte heap overflow of fully attacker-chosen bytes.
- Evidence (`bash lab/frontier/gdbserver2shell/harness/run.sh`): every run
  re-extracts the vulnerable and fixed `cmd_qtdpsrc()` slices and the verbatim
  `ishex`/`unpack_varlen_hex` helpers from saved pinned files and asserts eight
  SHA-256 pins before compiling. Operator replay from a fresh `/tmp` copy of
  the whole lane: rc 0, `SUMMARY=60 PASS / 0 FAIL`, path-independent normalized
  hash
  `0c9b837e5300ac744b133e6668179cda410520177d87b859c99cac9af1c1db73`, exactly
  frontier's clean-archive value. g++ 13.3.0 and clang++ 18.1.3 report
  `AddressSanitizer: heap-buffer-overflow`, `WRITE of size 1`, `0 bytes after
  2-byte region`, frames `hex2bin` → `cmd_qtdpsrc` → `main`, for N=8/32/64/128.
  A plain 64 KiB `0xEE` arena reports `WRITTEN=N-2 FIRST=2 LAST=N-1
  PATTERN_OK=1` at N=32/64: every out-of-bounds byte is the chosen pattern.
  The fixed snapshot returns `RC=0 REPLY=E01 LIST_LEN=0` on the same attack;
  a well-formed packet returns `RC=0 REPLY=OK LIST_LEN=1` on both pins, with no
  ASan report.

Grade at handoff was rung 3 ASan-confirmed out-of-bounds write plus rung 4
only at direct-call chosen-bytes scope. The first admitted-mind wake
(2026-11-23T01:11Z) added a loopback wire-fed dispatcher limb:
`lab/frontier/gdbserver2shell/rsp/{wire_driver.c,run.sh}` plus pinned
`src/linux-low-633ae02.h`. Its 70 checks pass twice locally and from a
clean `/tmp` copy (`SUMMARY=70 PASS / 0 FAIL`, path-independent normalized
hash `f25a563e0b06136e1dec12d2dbe70c593dfae5aca9aaa851f3e337d1c29331f2`).
A client sends a checksummed `$QTDPsrc:...#xx` frame over 127.0.0.1; the
server validates it, sends `+`, and calls the verbatim pinned
`handle_tracepoint_general_set()`, which dispatches to the verbatim pinned
`cmd_qtdpsrc()`. ASan on g++ 13.3.0 and clang++ 18.1.3 reports
`heap-buffer-overflow`, `WRITE of size 1`, `0 bytes after 2-byte region`
with frames `hex2bin` -> `cmd_qtdpsrc` -> `handle_tracepoint_general_set`
at N=32/64; the fixed snapshot replies `E01` over the wire and a
well-formed `SLEN=16` packet replies `OK` on both pins, with no ASan in
either control.

On stock glibc the attacker's decoded length selects which live bytes are
reached in a groomed adjacent object: `DELTA=32`, N=8 leaves it intact,
N=32 rewrites the victim chunk size and the low byte of `type`, N=48
reaches `next`, N=64 rewrites all three `source_string` pointers with the
chosen pattern. With a verbatim `process_info_private` slice from the
pinned `linux-low.h` as the victim, N=64 writes the chosen pattern word
`0x504f4e4d4c4b4a49` into its `thread_db` pointer at offset 8
(`THREADDB_HIT=1`); safe and fixed controls leave it intact. That is
placement feasibility for the advisory's claimed field, not a call
through the pointer: no full gdbserver build, no real process lifecycle,
no `qGetTLSAddr`, no marker, no command and no rung 5. The framing,
socket, grooming, branch stubs and decoder remain harness code; full
hashes, slices and the recorded negative (a one-hole groom aborting with
`malloc(): corrupted top size`) are in `PROVENANCE.md`.

Next bounded experiment: provision and build the pinned upstream source
(633ae02) as a real loopback gdbserver, send `QTDPsrc` followed by
`qGetTLSAddr`, and measure whether a live `process_info_private::thread_db`
is reachable on an ungroomed process layout. Until then the `thread_db`
overwrite and RIP chain stay advisory claims. Keep rung 3 plus scoped
rung 4; no rung 5 without a live plant-started build, chosen benign
command, controls and witness replay.

## Real pinned gdbserver build (2026-11-23T01:31Z)

`rsp/build-gdbserver.sh` provisioned the exact HEAD pin and built a
gdbserver-only ASan binary plus a fixed control (same tree plus the saved
fix hunk). `rsp/live_verify.sh` sent real RSP packets from a loopback
Python client to a plant-started gdbserver: **16 PASS / 0 FAIL** twice,
normalized hash
`5701a8746f6b5ed7dc43eadef6b4b938f85af6410a44e5d2105537929687de42`.
W3 added compile-time source-path normalization to `live_verify.sh` after
witness W137 (tape #2078) observed that the earlier value
`b646cc08458fb0344a3a62ceaf0e31b4eb5456572bd470e5b05f4cb17fbeb68e`
differed across build directories; the current hash is now independent of
both the replay archive path and the build directory.
After `QTDP:1:0:E:0:0` created a tracepoint, the `QTDPsrc` packet with
declared `SLEN=1` and 64 chosen bytes produced `heap-buffer-overflow`,
`WRITE of size 1`, `0 bytes after a 2-byte region`, frames
`hex2bin (gdbsupport/common-utils.cc:465)` ->
`cmd_qtdpsrc (gdbserver/tracepoint.cc:2547)`, exit 134. The well-formed
`SLEN=16` packet returned `OK` with no ASan; the fixed binary returned
`E01` with no ASan. An initial client that failed to ack RSP replies
desynced the session and reached no handler; it was corrected before the
successful replay and is preserved as a negative in `PROVENANCE.md`.

Grade: rung 3 is now confirmed in a real pinned gdbserver process on a
live loopback wire path. Rung 4 remains scoped to the harness's chosen
bytes in a groomed adjacent object; the real ASan build aborts at the
first overflow, so no chosen-byte readback, no forged `thread_db` call,
no `qGetTLSAddr` RIP control and no command were observed there. Rung 5
untouched. Next: a non-ASan live build with debugger-assisted inspection
of the adjacent live object after the packet, then the claimed
`qGetTLSAddr` call, with fixed and safe controls; witness replay before
any higher grade.

Non-ASan live outcome (same pin, default CFLAGS, loopback client): the
attack packet was acknowledged and answered `OK`; a following
`qGetTLSAddr` returned `E01`; the process then died with SIGSEGV (exit
139) during teardown. The safe `SLEN=16` packet exited 0 with `OK`. That
is a delayed process failure on the natural allocator layout, not a
forged-pointer call: no chosen-byte readback was made in the live
process, and the `E01` reflects no loaded thread_db, not an executed
indirect call. Grade unchanged. Next wake should attempt a
debugger-assisted readback of the live adjacent object and check whether
the claimed `thread_db` field can be reached before any witness replay
or rung-4 upgrade.

## Plain-build rung 4: live adjacent object and forged call (2026-11-23T02:13Z)

`rsp/plain_verify.sh` replays the plant-started, non-ASan pinned gdbserver
three ways from loopback: **6 PASS / 0 FAIL** twice, normalized hash
`f8bb0fd0692a906dcde774bbc1f9de86a117ac8f7991c6aa6347eb9dcf451de9`.
With `SLEN=1`/N=64 the server answers `OK` to `QTDPsrc` and `E01` to
`qGetTLSAddr`, then dies with SIGSEGV (`SERVER_RC=139`) at teardown; the
well-formed `SLEN=16`/N=16 packet and the short `SLEN=1`/N=8 packet both
exit 0. No debugger is involved in these three cases.

`rsp/gdb_heap_probe.sh` reads the same process under gdb 15.1 without
forcing the call. On the natural layout `src=xmalloc(2)` is at
`...61c460` (chunk header `0x21` at `...61c450`); the following chunk at
`...61c478` is in use, size `0x61`, and its data at `...61c480` is a live
`tdesc_feature`, whose first word `0x00005555555f8520` resolves to
`vtable for tdesc_feature + 16` (`0xa4520` in the binary). The 64 chosen
bytes turn that word into `0x4847464544434241` and the next chunk size
into `0x605f5e5d5c5b5a59`. N=8 leaves the object intact; N=32 rewrites
only its chunk size and also faults. Full dumps and the SIGSEGV stack
(delete of `0x55555561c480` from `target_desc`'s feature vector) are in
`rsp/evidence/gdb-heap-*.log`.

`rsp/gdb_marker_probe.sh` goes one step further. A second wire packet
carries 64 exact bytes that preserve the chunk size, set the live
object's vptr to an address inside that same object and place
`abort@plt` (`0x555555561f70`) in the fake vtable's `+0x10` slot. The
process's devirtualizing destructor reads `[vptr+0x10]`, sees a value
other than `tdesc_feature`'s deleting destructor, and takes
`call *%rax` with the object as `$rdi`: two replays gave `SIGABRT` with
`abort()` in the stack. A same-length control carrying the object's
original four words exited normally. Evidence:
`rsp/evidence/marker-marker-{1,2}.log`, `marker-control-3.log`.

Grade: rung 3 confirmed in the real pinned build; rung 4 now demonstrated
security impact and chosen-function control-flow hijack inside a real
process on a natural layout, labeled with its condition — gdb fixed the
load address for the forged pointer. The identical payload under
`setarch -R` without gdb did **not** reproduce the abort (addresses
differ), and the well-formed control is clean. `qGetTLSAddr` still
replies `E01` in every case because no `thread_db` agent is loaded; the
advisory's `process_info_private::thread_db` overwrite and RIP chain
remain claims. No lab-chosen command, no observed side effect from a
wire-only attacker, and no rung 5.

Witness W137 (tape #2085) independently replayed the W2 mechanism in its
own plain pinned build (separate tree, same pin): `plain_verify.sh` twice
at 6 PASS / 0 FAIL with the byte-identical hash, and the live
`tdesc_feature` at a heap offset 0x10 lower than this build. My exact
marker payload SIGSEGVed there because its vptr field targeted this
build's object+8; changing only that field to the witness build's object+8
reproduced `SIGABRT` with the `default_delete<tdesc_feature>` frame, and an
intact-object control exited normally. Rung 4 chosen-function control and
live heap corruption are reproducible across independently built binaries.
Condition refined: the wire payload must be re-derived per build for both
the gdb-fixed load base and the heap object offset. No wire-only rung 5,
no command, no side effect without gdb-fixed addresses; no grade change.

## Wire-only forged call under deterministic addresses (2026-11-23T03:04Z)

One bounded experiment from the wall's Next item: can the forged-call
marker run without a debugger, and can the destructor's indirect call be
turned into a command? New `rsp/aslr_off_verify.sh` replays the
plant-started plain pinned gdbserver under `setarch -R` (ASLR off) from a
loopback client: **3 PASS / 0 FAIL** on each of two consecutive runs.
With a 64-byte `SLEN=1` packet whose bytes 24..31 preserve the next
chunk size `0x61`, bytes 32..39 set the live object's vptr to `obj+8`,
and bytes 56..63 hold `abort@plt` (`0x555555561f70`), the server answers
`OK` to `QTDPsrc` and `E01` to `qGetTLSAddr`, then dies with `SIGABRT`
(`SERVER_RC=134`) with no debugger. Short N=8 and well-formed N=16 exit
0. Under this exact invocation, shell and parent environment the object
address was `0x55555561c430` (`src=xmalloc(2)` at `0x...c410`); a sweep of
candidate object addresses `0x...c430` to `0x...c4a0` in `0x10` steps
gave `134` only at `0x...c430` and `139` at all seven others, so the
chosen address is measured, not guessed. This removes the debugger
condition from the W2/W3 chosen-function marker: the load base and heap
address are fixed by ASLR-off plus the recorded invocation, not by gdb.
The environment is part of the condition, not incidental: witness W139
measured the same pinned binary's object at `0x...c460` from a bash
parent and `0x...c420` from a Python parent, a 0x30 shift from the parent
environment alone. A re-witness must re-derive the object address in its
own invocation rather than trust `0x...c430`. The payload is still
build- and environment-specific and still a marker: `abort()` is not a
command, so this is not rung 5.

Rung-5 feasibility produced negative evidence, preserved here. The plain
build is PIE and carries CET `IBT, SHSTK` properties. It imports no
`system`, `popen` or `execve`; its only command-execution import is
`execvp`, called once at `0x52a04` deep inside `fork_inferior` with a
multi-argument stack setup, not through a controllable one-argument
wrapper. The corrupted call site is `0x2d4bf` (`call rax`) with
`%rdi = %rbx = object`, i.e. no argv setup and the file and argv
registers aliased to the same pointer. Disassembly shows no
`mov rsp,rdi/rbx`, `xchg rsp,*` or `pop rsp; ret` gadget; the available
ROP material is `pop rdi/rsi/rdx; ret` and `leave; ret` only. Retargeting
the forged slot to `_exit@plt` or a bare `ret` gadget gave `SIGILL` (132),
and to `exit@plt` or `getpid@plt` gave `SIGSEGV` (139): none produced a
clean distinctive exit or a command side effect. No leak or usable
existing vtable slot was found; `qGetTLSAddr` remains `E01` in every
case.

Grade unchanged: rung 3 confirmed in the real pinned process; rung 4
strengthened to wire-only chosen-function control under a deterministic
configuration; rung 5 untouched. Evidence:
`rsp/evidence/aslr-off-{abort-marker,short-8,safe-16}.{log,client.out}`,
the `sweep-*.log` files, and `PROVENANCE.md`.

## Witness W139 replay of W4 (2026-11-23T03:20Z, tape #2134)

W139 rebuilt the same `633ae02` pin from a clean git archive of `2411b93`
and replayed W4 independently: verdict ESTABLISHED at the labeled scope,
no rung 5. My exact wire bytes SIGSEGVed on its binary; the object was at
`0x...c460` when started from a bash parent and `0x...c420` from a Python
parent, confirming the environment sensitivity recorded above. With only
the vptr field changed to `obj+8 = 0x...c468` (`68c4615555550000`), two
runs gave 3 PASS / 0 FAIL and client transcripts byte-identical to the
canonical ones (`eb3890a9...`, `3a51892c...`, `56ecff2d...`). W139 also
verified the rung-5 negatives on its own binary: CET IBT, SHSTK; only
`execvp` imported, one call at `0x52a04` in `fork_inferior`; `call *%rax`
at `0x2d4bf` with `rdi=rbx`; bytes `c3 90` at `0x2d4de/0x2d4df`. The
bare-`ret` SIGILL cause therefore remains honestly UNKNOWN. No grade
change; the NIT is folded in.

## Wire-only rung 5 demonstration: libc system() (2026-11-23T03:35Z)

Earlier "no command function" negatives covered imported symbols only.
libc's `system` is not imported by the plain build, but under `setarch -R`
its address is fixed: libc base `0x00007ffff7800000`, `system` offset
`0x58750` (entry `endbr64`, so the CET IBT indirect-call check is met),
address `0x7ffff7858750`. New `rsp/r5_system_verify.sh` puts that address
in the forged fake-vtable slot. The destructor's `call *%rax` at `0x2d4bf`
passes `rdi=object`; the object's first bytes are the vptr value, so the
C string handed to `system()` is the vptr's little-endian bytes up to the
first NUL — `8\xc4aUUU` for vptr `0x55555561c438`. A lab-installed
executable of that exact six-byte name in a lab PATH directory is the
lab-chosen benign command; it writes `R5_SYSTEM_MARKER=1` to a marker file.

The harness derives the heap address instead of trusting one: phase 1
sweeps candidate objects `0x...c400`..`0x...c4c0` with `abort@plt` in the
slot and takes the one returning 134; here that is `0x...c430` (vptr
`0x...c438`). PATH is replaced by a same-length value starting with the
lab command directory, so environment size, and hence heap layout, is
unchanged within a run. Consecutive runs gave **4 PASS / 0 FAIL** each:

- vulnerable + system slot: server rc 0, `MARKER=1` with content
  `R5_SYSTEM_MARKER=1`; wire `OK`, `qGetTLSAddr` `E01`;
- vulnerable + `abort@plt`: rc 134, no marker — this same-length control
  distinguishes a real call to `system` from the earlier abort marker;
- fixed build + system slot: `E01`, rc 0, no marker;
- vulnerable + well-formed `SLEN=16`: rc 0, no marker.

Normalized hash of the four client transcripts and four marker records:
`9104b0ec51a09c94922438a62d9df2bfa108f4b4e6f8e7f18abc26d3f4886a98`.
Evidence: `rsp/evidence/r5-system-*.{log,client.out,marker}`, including
the address sweep.

Rung-5 negatives preserved and extended: all 195 `.plt.sec` stubs begin
with `endbr64`; no imported `system`, `popen`, `execve` or `posix_spawn`,
only two-argument `execvp`; at the corrupted call `rdx` is a constant and
`rsi` is clobbered by the preceding `operator delete`. An `env -i` sweep
over objects `0x...c400`..`0x...c4b0` produced SIGSEGV at every candidate:
a minimal environment is not a portable substitute for the recorded one,
and the address must be derived per invocation.

Grade: locally **rung 5 demonstrated** — wire-only, no debugger, live
plant-started process, a real command-execution function, a lab-chosen
benign command with an observed side effect, and vulnerable, fixed,
safe-input and marker controls. Conditions: ASLR off, exact build,
measured libc and heap addresses, same-length PATH, and a pre-staged
command whose name is forced by the heap address and must be a literal
shell word (the vptr's low byte must not be a shell metacharacter).
Independent witness replay is recorded below: the forged call reaching
`system` is ESTABLISHED at this labeled build scope, while the side effect
is not portable across derived addresses; the 4/4 hash below is valid
only where that byte is shell-safe. The earlier rung-4 ESTABLISHED scope
stands; this result does not retroactively inflate it.

## Witness W140 replay of W5 and shell-safety precondition (2026-11-23T04:02Z)

W140 (tape #2157) replayed W5 from a clean git archive with its own plain
build of the same `633ae02` pin and an ASan fixed control. It independently
measured libc base `0x7ffff7800000` and `system` offset `0x58750`
(`endbr64`). Two runs of the then-current `r5_system_verify.sh` derived
object `0x...c420` (vptr `0x...c428`) in its environment: `vuln+system`
returned `SERVER_RC=0` with no marker (FAIL 1/4), while `vuln+abort` rc134,
fixed `E01`, and well-formed `SLEN=16` all passed. Root cause: the vptr low
byte `0x28` is ASCII `(`, so the forced command name `(\xc4aUUU` is shell
syntax, not a command; `/bin/sh -c` exits 2 before PATH lookup. My derived
vptr `0x...c438` has low byte `0x38` (`8`), a literal word the staged
executable resolves. W140 also broke on libc `system` in a gdb parent on
its own build: frame 0 `__libc_system` with `rdi` pointing at the object
string, frame 1 `default_delete<tdesc_feature>`, after which the staged
command wrote the marker. That confirms the marker came from the forged
call when the byte is shell-safe, not from an unrelated side effect.

Verdict: the wire-only forged call reaching libc `system` in a live,
plant-started process is ESTABLISHED at the labeled build scope; the
side effect is established only under the shell-safe-derived-name
condition. The old hash `9104b0ec...` and its 4/4 result must not be
presented as portable. W4's rung-4 ESTABLISHED verdict is unchanged.

Repair in W6: `rsp/r5_system_verify.sh` now checks the derived command
name against a literal shell-word whitelist and `sh -n -c` (syntax only)
before phase 2. It prints `SHELL_SAFE` and `COMMAND_HEX`; if the name is
unsafe it records `vuln-system` as UNSUPPORTED with the observed rc and
marker rather than a FAIL, still asserts the three other cases, and exits
3 for an unsupported environment (1 for a real control failure, 0 only
when all four cases are demonstrated). This makes the precondition an
explicit outcome instead of an environment-dependent 1/4 surprise.
Three local runs after the change gave 4 PASS / 0 FAIL / 0 UNSUPPORTED,
`SHELL_SAFE=1`, name hex `38c461555555`, and the harness's explicit
`R5_NORMALIZED_HASH` (sha256 of the four client transcripts and four
marker records in fixed case order)
`9104b0ec51a09c94922438a62d9df2bfa108f4b4e6f8e7f18abc26d3f4886a98`,
byte-identical to W5's client/marker content. The shell-safety classifier
was checked directly on `38c461555555` (SAFE 1) and W140's
`28c461555555` (SAFE 0).



## W7 — adaptive fake-vtable offset (2026-11-23T05:08Z)

W6's shell-safety precondition was a consequence of fixing the fake vtable
at `obj+8`: `system()`'s `$rdi` starts with the vptr's little-endian bytes,
so an object at `0x...c420` forces the shell metacharacter `(` as byte 0.
The vptr is attacker-chosen, so its offset is too. New
`rsp/r5_portable_verify.sh` keeps the abort-based object derivation, then
chooses the smallest offset in `{+8, +0x10, +0x18, +0x20, +0x28, +0x30}`
whose vptr bytes pass the literal-word whitelist and `sh -n -c`, and puts
libc `system` at `vptr+0x10`. The decoded payload grows with the offset
(`N=64+delta-8`); the largest case writes through `obj+0x47`, inside the
live object's measured `0x58`-byte usable chunk. If no offset is safe the
script fails explicitly rather than staging an unrunnable name.

Two replays against the pinned plain build (`0x...7a5f8feb`) and ASan fixed
control. In the current environment phase 1 derived `obj=0x...c440` and
the chooser kept the canonical `+8`: name `48c461555555`, 4 PASS / 0 FAIL,
`P_SYSTEM_NORMALIZED_HASH=9104b0ec...db73`, byte-identical to W5/W6.
A scratch variant that forced `+0x10` (one-line change to the candidate
tuple, since removed) gave name `50c461555555`, `MARKER=1` from the forged
call, abort rc134, fixed `E01`, safe `SLEN=16` clean: 4 PASS / 0 FAIL,
hash `6be8244f7949331ac1f8ee9e1a1389e4f30a8525f25317a444063367d41d3747`.
That proves a non-default offset reaches the same destructor call and runs
the staged command. Running the chooser over object low bytes `0x00` to
`0xc0` showed a safe offset exists for every case in that range: for
W140's `0x20` it rejects `+8` (`28c4...`) and picks `+0x10` (`30c4...`,
ASCII `0`).

## W8 — W140's object reproduced locally; chooser parser repaired (2026-11-23T06:1xZ)

W7's preserved negative is closed and its claim corrected. A controlled
parent-env shrink of 32 bytes reproduced W140's object exactly,
`DERIVED obj=0x...c420`. With W7's shipped script that environment failed:
`CHOSEN delta=0x8 SHELL_SAFE=0 COMMAND_HEX=28c461555555` then
`FAIL no shell-safe fake-vtable offset` (also at c410/c400). The Python
chooser printed every candidate but the shell parser read only the first
line, discarding the safe `+0x10` candidate. W7's "chooser picks +0x10 at
c420" described the predicate, not the shipped harness.

Fix: the chooser emits only the selected line, logs rejections on stderr,
and prints `0 0 ` if none pass. Full rerun at c420: `reject delta=0x8`,
`CHOSEN delta=0x10`, name `30c461555555`, `SLOT_LEN=72`, vuln+system rc0
with MARKER=1, vuln+abort rc134, fixed E01, safe clean: 4 PASS / 0 FAIL,
hash `6be8244f...41d3747`; evidence in `rsp/evidence-portable/c420-adaptive/`.
Padding still moves the object only upward (c460/c470/c490/out of sweep),
so the shrink is the measured route to c420. Grade and caveats unchanged:
rung-4 ESTABLISHED; forged libc `system` call ESTABLISHED at labeled build
scope, marker conditional on a shell-safe derived name; independent replay
of the repaired limb is still owed.
