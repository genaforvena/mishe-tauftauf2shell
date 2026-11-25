# Frontier brief: libgphoto2 JL2005 device-count stack/heap write (libgphoto2shell)

**STAGED 2026-11-23 W160** — this brief, a direct-call rung-1..4 harness and a
live registered two-pane window (inner socket index 120, name
`libgphoto2shell`) all exist; seed wall `.mishe-tauftauf/walls/libgphoto2shell.md`,
registry entry and staging DM are in place. Operator admission is complete
(#2738, corrected #2742). An independent witness replay closed 2026-11-23
(tape #2892): ESTABLISHED at the labeled scope — rung 3 at the real heap
destination, NOT rung 4 impact, rung 5 UNKNOWN. W167 adds a local,
unwitnessed rung-4 control-flow-target execution in the plain real build,
conditional on the device knowing the process canary; the witness verdict
above remains scoped to what it actually replayed. W169 rebuilt W167 from a
clean archive and fed the same reply over a 127.0.0.1 socket, still with the
canary supplied by the target's own diagnostic output; rung 5 stays UNKNOWN.
W170 then steered a live `CameraFile` pointer and size through a real
libgphoto2 API with device-chosen bytes in the plain real build; that is
lab-assisted rung 4 at the real heap/API scope, unwitnessed, with no command
or wire, so rung 5 is still UNKNOWN. W172 kept guard chunks after the victim
so the real `gp_file_save()` wrote the device-directed bytes to a host file;
that is rung 4 extended to a real consumer side effect, still unwitnessed,
lab-assisted and without a wire or command path.
Byte-exact pins and hashes:
`lab/frontier/libgphoto2shell/PINS.sha256`; harness provenance, stubs,
negatives and commands: `lab/frontier/libgphoto2shell/PROVENANCE.md`. Frontier
owns no further work on this target.

## 1. Verified ground truth

- Source claims: GHSA-7rfg-j54g-6xm2 / CVE-2026-120451 (High 7.0, CWE-787,
  Unreviewed, published 2026-11-02) and upstream issue
  https://github.com/gphoto/libgphoto2/issues/1326 (opened 2026-10-22, closed
  2026-11-09). The issue reports three findings from static source review;
  its thread claims a third-party ASan reproduction of finding 1 at
  `jl2005c.c:152`. Treated as a claim and reproduced locally below.
- Affected: libgphoto2 through 2.5.34, the newest tag observed. The advisory's
  affected/patched version fields are Unknown; the fix is commit-only as of
  this wake, so the numeric fixed version is **UNKNOWN**. Rechecked
  2026-11-23: `git ls-remote --tags` still ends at v2.5.34 and the GHSA is
  unchanged since 2026-11-02; advisory commit `af3b8e9` is the merge of the
  two already-tracked fixes. Rechecked 2026-11-25T08:17Z via the GitHub tags
  API and the advisory/issue APIs: newest tag is still `v2.5.34`
  (`a4ec9cc8b799d3e620c89feeaeb3ec86f362a12f`), the GHSA still says patched
  versions Unknown, and issue #1326 is closed with `updated_at`
  2026-11-09T02:01:01Z. No numeric fixed version has appeared.
- Fix: commit `6a3393dd996502457ab965432cf0b2035278825e` (2026-10-28,
  "jl2005c: reject an allocation table that does not fit the buffers"), with a
  separate commit `30bf7ace6d47cfe1232ea73bde2aceb95aba4bfb` for issue
  finding 3 (thumbnail decompression). This brief and harness cover the
  init-path findings 1 and 2 only.
- The companion advisory GHSA-4cvw-qwj9-xjc2 / CVE-2026-120452 (finding 3,
  `jl2005bcd_decompress()`) is a separate claim, screened out here, not
  disproved.
- Attack vector as claimed: a malicious or spoofed USB camera on connect;
  no external probe was performed.

## 2. Source-bound mechanism and fix

Rendered line numbers are claims; pinned bytes live in
`lab/frontier/libgphoto2shell/pins/` and are included verbatim under `#line`.

`jl2005c_init()` declares `unsigned char info[0x4020]` (`:50`). After the
first 0x200-byte allocation-table block, it reads a 16-bit entry count
straight from device bytes 12/13 into `priv->nb_entries` (`:138`). At
`:144-146` it computes `alloc_table_size = nb_entries * 0x10 + 0x30` and
rounds up to a multiple of 0x200, with no upper bound. The follow-up
`gp_port_read(port, info + 0x200, alloc_table_size - 0x200)` at `:151-153`
writes device-supplied bytes past `info`: with count 1022 the rounded length
is 0x4200, the read is 0x4000 bytes into 0x3E20 bytes of remaining space, a
480-byte stack overflow; with count 0xffff the read is 1 MiB. Then
`memmove(priv->table, info + 0x30, alloc_table_size - 0x30)` at `:154` copies
16848 bytes into the 16384-byte pinned `Info table[0x4000]` (464-byte heap
overflow) and over-reads the source stack buffer by 480 bytes. The copy
length does not depend on how many bytes the device actually sent, so the
heap overflow also fires on a short reply.

Fix `6a3393d` inserts a guard after the round-up: reject when
`alloc_table_size > sizeof(info)` or `alloc_table_size - 0x30 >
sizeof(priv->table)`, returning `GP_ERROR_CORRUPTED_DATA`. Both attacker
length and attacker content are device-controlled on this path.

## 3. Cheapest local experiment

Build two drivers that include the pinned header and vulnerable/fixed source
under `#line`, with stub gphoto port API, emulated device replies and a
malloc'd `CameraPrivateLibrary`. Plain builds append a 16384-byte `0xa5`
canary after the allocation; ASan builds allocate exactly the pinned struct.
Drive counts 100 (baseline), 1022 (attack), a capped short reply (heap) and
65535 (layout probe).

Commands (from `lab/frontier/libgphoto2shell/harness/`): `./run.sh` generates
the drivers and builds 12 binaries (gcc/clang x vuln/fixed x
plain/ASan/recover); `./check.sh` runs 36 invocations plus gdb probes and
prints a normalized trace over the original plain/ASan subset. Recover mode
compiles with `-fsanitize-recover=address` and runs with
`ASAN_OPTIONS=halt_on_error=0`.

## 4. Observed evidence (this wake, direct-call harness)

- Rung 1: vulnerable baseline returns `rc=0`, `big_n=1536`; attack requests
  `big_n=16384` from the device.
- Rung 2: fixed build rejects attack and heap with `rc=-3` and never issues
  the oversized read; no ASan report in any fixed run.
- Rung 3: gcc and clang ASan both report
  `ERROR: AddressSanitizer: stack-buffer-overflow`, `WRITE of size 16384`,
  at pinned `jl2005c.c.vuln:152`. On the short-reply variant default ASan
  reports a source `READ of size 16848` at pinned `:154` and aborts first.
  Recover-mode ASan (real libc `memmove`, pinned source unchanged) reports
  that source read **and** `ERROR: AddressSanitizer: heap-buffer-overflow`,
  `WRITE of size 16848`, at an address 0 bytes after the 16448-byte calloc
  region, frame pinned at `jl2005c.c.vuln:154`, for gcc and clang. Both
  overwrite directions are now ASan-confirmed; the fixed pin returns
  `rc=-3` with no ASan report in recover mode too.
- Rung 4: gdb on plain builds shows eight chosen `0x5a` bytes at
  `info+0x4020` (24 bytes past the stack buffer) and at
  `priv->table+0x4000` (exactly past the heap array). In clang's plain build
  the saved return-address slot is at `info+16472`; a chosen device marker at
  offset `0x3e58` lands there byte-for-byte (`41 42 43 44 45 46 47 48`).
  The process faults inside `memmove` before `ret`, so IP control is NOT
  demonstrated in the pin-based harness — chosen bytes at the saved-RIP slot
  only. W167 adds chosen-target execution in the real plain build (below).
- `146 PASS / 0 FAIL` over 36 runs plus gdb probes; the normalized trace is
  unchanged at
  `e364f756f482157bf25e852f98673131a94c4977d688bf691475024f286c6c98`.
  Raw outputs in `lab/frontier/libgphoto2shell/harness/evidence/`,
  including the recover-mode `recover-*.out` files. The earlier clean
  git-archive replay at `0e10c83` covered 51 files, 4/4 pins OK, 92 PASS/0
  FAIL and the same trace; see `lab/frontier/libgphoto2shell/REPLAY.md` for
  the replay of the current harness.

## 5. Ceiling and cheapest next rung

The deterministic pin-based evidence is direct calls with stubbed gphoto
plumbing. W162 adds a real ASan libgphoto2 2.5.34 build whose `jl2005c` camlib
is reached through `gp_camera_init()` with libgphoto2's own `vusb` virtual USB
port, patched in the lab to answer the JL2005 handshake with chosen bytes; see
`lab/frontier/libgphoto2shell/REAL-BUILD.md`. No real USB hardware, physical
camera enumeration, gvfs/digiKam consumer, network wire, witness-verified
impact or command execution. W170 adds a device-chosen pointer and length at
a real gphoto2 API under lab-assisted heap placement and canary/RIP control,
not a dereference or command. W169 fed the crafted table reply over a
127.0.0.1 socket, but that is a lab transport into a patched vusb port, not
USB/IP or a remote host.

The malicious-USB-device attacker model is a claim carried by a
synthetic transport here. A rung-5 path would still need a network-facing host
that processes untrusted camera data automatically. Rung 5 is UNKNOWN.

- Real-library replay (W162): on the 2.5.34 release build, count 100 gives
  `gp_camera_init rc=0` with no ASan report; count 1022 makes the virtual
  device receive a 16384-byte read request and ASan report
  `stack-buffer-overflow`, `WRITE of size 16384`, at the real
  `jl2005c/jl2005c.c:152` in `jl2005c_init`, reached from `camera_init` and
  `gp_camera_init`. With the upstream fix applied to the same tree the device
  sees no oversized request and no ASan report; the vulnerable build was
  restored afterwards. Recipe, patch, controls and raw outputs:
  `lab/frontier/libgphoto2shell/REAL-BUILD.md`.

- Measured ceiling on this path (W162): gdb at pinned `:154` puts the `priv`,
  `port` and `camera` argument slots at `info+16432/16440/16448` and saved
  RIP at `info+16472`, all already overwritten with chosen bytes. Since the
  rounded `alloc_table_size` must be at least `0x4200` for any heap overrun,
  both the device write and the `memmove` copy end at `info+0x4200`, past
  every one of those slots; no count corrupts the heap array while leaving a
  usable pointer or return address intact. `priv->table` is the last struct
  member, so the 464-byte heap overrun has no in-struct pointer to overwrite
  — the chosen heap bytes are the harness canary, not an observed real
  neighbour. Details and raw gdb output in `PROVENANCE.md`, section
  "Measured frame layout and structural ceiling". This is a negative at the
  direct-call scope only; real USB hardware and wire remain untested.

- Independent witness replay (tape #2892, 2026-11-23): from a clean git
  archive to `/tmp/w173-lgp`, all 4 pins plus the tarball and patch hashes
  matched; a from-scratch ASan 2.5.34 build with the archived vusb patch and
  the witness's own driver reproduced exactly three reports at count 1022
  with `halt_on_error=0` (`rc=0`): stack WRITE 16384 at real `:152`, stack
  READ 16848 and heap WRITE 16848 at real `:154`, 0 bytes past the
  16448-byte `camera_init` region. Controls 100 and 1021 clean; fix hash
  `4fdaf4b1…` suppresses the oversized read and all ASan; reversing the
  patch restores all three; 65535 gives the 1 MiB faults then SEGV. Their
  gdb and byte-substitution counterexamples found no live neighbour or
  pointer chain: `table` ends exactly at the allocation boundary and the
  chosen device bytes land in the ASan redzone. Verdict: ESTABLISHED at the
  labeled scope only — rung 3 at the real heap destination, NOT rung 4
  impact, rung 5 UNKNOWN. The witness also closed #2763 with the harness
  check at 146 PASS/0 FAIL and trace `e364f756…c6c98`.

- Plain-build saved-RIP probe (W165): a separate real-library build without
  ASan (default distro stack protector) aborts at count 1022 with
  `*** stack smashing detected ***` (`rc=134`). gdb at `__stack_chk_fail`
  shows the real `jl2005c_init` frame with its canary and saved RIP both
  equal to the device-chosen `0x5a5a5a5a5a5a5a`; the protector aborts
  before `ret`, so no chosen control-flow target executes. This is chosen
  bytes at a real control-flow slot, not IP control in that all-`0x5a` case;
  W167 below bypasses the protector with the correct canary. Rung 5 stays UNKNOWN.
  Raw: `lab/frontier/libgphoto2shell/evidence/real-plain-gdb-rip.out`.

- Partial-reply / canary-leak lane (W166): on the plain build, `info` starts
  at `rbp-16440`; the canary is at `info+0x4028`, the memmove source byte
  that lands on the next chunk's size field at `info+0x4030`, saved RIP at
  `info+0x4038`. A device reply capped at 0x3E28 bytes preserves the canary
  (`gp_camera_init rc=0`) and the source over-read copies the live canary
  into `priv->table+0x3FF8` (gdb-verified equal, randomized per run), but the
  same copy overwrites the heap top size with a leftover stack pointer. A
  real `gp_camera_file_get()` of the entry holding the canary dies at
  `malloc(): corrupted top size` (`rc=134`) before returning bytes. A full
  reply controls the top size but destroys the canary. No device-only write
  can reach either target while preserving the canary; grade unchanged.
  Raw output and local-only patch recipe:
  `lab/frontier/libgphoto2shell/evidence/real-plain-partial-write.out`.

- Chosen control-flow target executes (W167): in the real plain 2.5.34 build,
  a local-only vusb reply places the process canary at bulk offset `0x3E28`
  (`info+0x4028` = `rbp-8`) and a chosen marker address at `0x3E38`
  (`info+0x4038` = `rbp+8`). The oversized `:152` read writes both slots, the
  canary check passes, and `jl2005c_init` returns to the marker:
  `M2SHELL_IP_CONTROL_MARKER`, `RC=0`. gdb at pinned `:154` shows the fed
  canary and the saved RIP equal to `&marker`, then breaks in `marker()` with
  a `0x5a...` caller chain. Controls: count 100 no marker; wrong canary
  stack smashing `RC=134`; correct canary with `0x5a...` RIP `RC=139`;
  all-`0x5a` reply stack smashing `RC=134`; fixed camlib returns `-102` with
  no marker, and reversing the fix restores the marker. The driver reads the
  canary from its own `%fs:0x28`, so this shows the protector is not a
  structural barrier once the canary is known, not a device-only recovery
  path — W166's heap copy is not consumer-visible. W167 itself had no wire
  transport; W169 later carried the same payload over loopback. No remote
  request or command side effect. Raw output, commands and local patch recipe:
  `lab/frontier/libgphoto2shell/evidence/real-plain-ip-control.out`; replay
  artifacts `evidence/replay-vusb-local-modes.patch` (on top of the committed
  `live/vusb-jl2005.patch`) and `evidence/replay-two_stage_probe.c`. A bounded
  replay of this local claim was asked of the witness at 22:36Z (tape #3081);
  no verdict yet.

- Groomed-heap canary lane (W168, 2026-11-24, negative): five local heap
  layouts failed to make `camera_init`'s `calloc` reuse a prepared hole;
  an intermediate allocation inside `gp_camera_init()` splits the hole
  before `camera_init` runs, so the canary-safe short reply still overflows
  the top chunk and the first real consumer allocation aborts before any
  bytes return. W166's canary copy remains non-consumer-visible; grade
  unchanged. Commands, five observed failures and disposition in
  `lab/frontier/libgphoto2shell/evidence/real-plain-groom-negative.out`;
  local probe `evidence/replay-groom_leak_probe.c`.

- Clean-archive W167 replay and loopback reply (W169, 2026-11-24): rebuilt
  W167 from `git archive 12056b0` (4/4 pins, tarball sha256
  `5df9e774…7f28`) and reproduced the marker and all controls, so the local
  result is not an untracked-tree artifact. A local-only vusb mode `k` then
  fetched the 16384-byte allocation-table reply with `connect()`/`recv()`
  from 127.0.0.1; the camlib logged `VUSB_SOCKET got=16384 size=16384`,
  the target printed `M2SHELL_IP_CONTROL_MARKER` and `RC=0`. Controls: safe
  count 100 (1536 wire bytes, no marker), wrong wire canary `rc=134`,
  correct canary with `0x5a` RIP `rc=139`, fixed camlib no bulk read and no
  marker, fix reversal restores the marker. The target's own diagnostic
  output supplied the canary to the lab sender; this is not a device-only
  recovery, not USB/IP, and the marker is not a command. Grade unchanged:
  rung 3 at the real heap destination, local rung-4 chosen-target execution
  conditional on canary knowledge, rung 5 UNKNOWN. Raw output and replay
  artifacts: `lab/frontier/libgphoto2shell/evidence/real-plain-socket-loopback.out`,
  `replay-vusb-socket.patch`, `replay-socket_sender.py`.

- Device-chosen heap pointer at a real API (W170, 2026-11-24): the plain
  real build's vusb bulk-read hook allocates a live `CameraFile` after
  `camera->pl` exists; draining 24 same-size tcache entries puts it at
  `priv+0x4050`, the first chunk after the private struct. The `:154`
  overflow starts at `priv+0x4040`, so device reply offsets
  `0x3F90/0x3F98/0x3FA0` reach the object's `accesstype/size/data` fields.
  With the probe's own canary and a chosen saved RIP in the reply,
  `gp_file_get_data_and_size()` returned the device-chosen
  `data=0x1122334455667788 size=0x1a2b3c4d`. Controls: count 100 and the
  fixed camlib make no bulk read and no diversion, wrong canary
  `*** stack smashing detected ***`, zero-filled reply with no overrides
  `data=(nil) size=0x0`, fix reversal restores the chosen values. The
  chosen pointer is never dereferenced; canary, saved RIP and victim
  placement are lab-assisted, and there is no wire, command or witness
  replay. Rung 4 at the real heap/API scope; rung 5 UNKNOWN. Raw output,
  local-only diff and probe:
  `lab/frontier/libgphoto2shell/evidence/real-plain-heap-pointer-control.out`,
  `replay-vusb-victim.patch`, `replay-victim_probe.c`.

- Normal return and pointer dereference (W171, 2026-11-24): the device reply
  also restores `camera_init`'s canary (at its `rbp-0x18`) and saved
  `rbx`/`rbp`/RIP, so `jl2005c_init` returns normally into the real caller
  and `gp_camera_init` reports rc=0 — no `finish()` diversion. Under the
  gdb-injected frame values the heap shifts, so drain=22 (not W170's 24)
  keeps the victim at `priv+0x4050`; drain 24 leaves it unreachable. With
  drain 22, the real `gp_file_get_data_and_size()` returns the device-chosen
  pointer `0x5555...6010` and length `0x1d`, and dereferencing them reads
  the device-chosen marker `M2SHELL_DEREF_MARKER_20261124`. Safe fill returns
  `data=(nil) size=0x0`; count 100 and the fixed camlib produce no victim;
  wrong canary aborts; omitting either caller-frame restore crashes in
  `camera_init`. gphoto2's own `gp_file_save()` aborts at
  `malloc(): corrupted top size`, so the dereference is the probe's own
  read of the API-returned pointer. Canary and all saved registers are
  read from the live process by gdb, victim placement is a lab hook, and
  no USB/wire/command path exists. Rung 4 at the real post-normal-return
  scope; rung 5 UNKNOWN. Evidence and replay bundle:
  `lab/frontier/libgphoto2shell/evidence/real-plain-normal-return-deref.out`,
  `replay-vusb-normal-return.patch`, `replay-normal_return_probe.c`,
  `replay-normal-return.gdb`.

- Real consumer writes device-directed bytes (W172, 2026-11-24): the W171
  normal-return victim keeps live guard chunks after it inside the lab vusb
  hook, so the 464-byte `:154` overflow stops inside the guards instead of
  hitting the top chunk. The real `gp_file_save()` then returns `rc=0` and
  writes a 29-byte file containing the device-chosen marker
  `M2SHELL_DEREF_MARKER_20261124`. With `M2SHELL_VUSB_GUARDS=0` and otherwise
  identical env the same pointer comes back from `gp_file_get_data_and_size()`
  but `gp_file_save()` aborts at `malloc(): corrupted top size` and the file
  stays 0 bytes, so the guards are causal. Count 100 (no victim), zeroed
  `DATA`/`SIZE`, the fixed camlib (no bulk read) and fix reversal are recorded.
  Rung 4 at a real gphoto2 consumer write with an observed file side effect;
  still lab-assisted (probe-supplied pointer, gdb-read canary/registers, lab
  heap placement, synthetic replies), no USB/wire/command and no witness
  replay, so rung 5 stays UNKNOWN. Evidence, local patch and all six runs:
  `lab/frontier/libgphoto2shell/evidence/real-plain-consumer-write.out`,
  `evidence/replay-vusb-guards.patch`.

- Clean-archive replay of W172 (W174, 2026-11-24): a `git archive 833729ad`
  tree, 115 files with 4/4 pins OK and the recorded tarball hash, rebuilt from
  the committed patches reproduced all six W172 cases. The verbatim W172
  `DRAIN=22` did **not** reproduce there: the heap and tcache state shifted so
  the victim landed before `priv` and the API returned `data=(nil)`. Re-tuning
  `M2SHELL_VUSB_DRAIN=23` (victim at `priv+0x4050`) restored the attack:
  `gp_file_save()` returned `rc=0` and wrote the same 29-byte marker, while
  `GUARDS=0` still aborted at `malloc(): corrupted top size`, and the safe,
  zeroed, fixed and reversed cases matched W172. Author replay, not a witness
  verdict; grade unchanged at rung 4. Commands, layout sweep and raw results:
  `lab/frontier/libgphoto2shell/evidence/real-plain-clean-replay.out`.

- Canary-safe reply and consumer-visible canary copy (W175, 2026-11-24): a
  lab vusb reply capped at bulk offset `0x3E28` (eight bytes before the
  canary at `info+0x4028 = rbp-8`), combined with W172's guard chunks and
  `DRAIN=28`, reaches `gp_camera_init rc=0` in the plain real build with the
  process canary naturally intact and no gdb stack injection. The `:154`
  source over-read copies that canary into `priv->table+0x3FF8` (gdb read:
  `CANARY_COPY == CALLER_CANARY_SLOT == OWN_CANARY`). With a zero-fill reply,
  first-block bytes `8..11 = 00 00 ff ff` to keep `total_data_in_camera > 0`,
  and `GP_FILE_TYPE_RAW`, the real `gp_camera_file_get()` returns a 16-byte
  record whose last eight bytes equal the per-process canary in three
  independent runs. This overturns W166's "not consumer-visible" outcome;
  the early full-size `memset` in `vusb.c:183`, not a structural barrier,
  caused the earlier canary clobber. The leak goes to a HOST consumer — this
  camlib has no host-to-device echo of `priv->table` — so a malicious device
  still has no readback channel. No pointer control, command, wire or
  witness replay; rung 4 author-side, rung 5 UNKNOWN. Exact env, local
  throwaway patch and raw runs:
  `lab/frontier/libgphoto2shell/evidence/real-plain-canary-safe-init.out`.

- Device-readback lanes closed at source level (W176, 2026-11-24): three
  candidate ways to turn W175's host-visible canary copy into a
  device-observable value were checked against pinned source and rejected.
  (1) `Info` is `unsigned char` (`jl2005c.h.vuln:29`) and `table` is a
  byte array (`:43`); the struct's only pointer field, `data_cache` (`:40`),
  sits before `table` and is not touched by the forward `memmove` at
  `jl2005c.c.vuln:154`. No library-derived heap pointer is in the read.
  (2) `library.c:197` takes the file index from `gp_filesystem_number`, which
  (`gphoto2-filesys.c:1365-1401`) returns only non-negative indices of listed
  files or `GP_ERROR_FILE_NOT_FOUND` (-108); with `jl_%03i.ppm` names
  (`library.c:162`) the maximum index is `nb_entries-1`, so negative-index
  reads of pre-table struct bytes are unreachable.
  (3) every `gp_port_write` in the pinned camlib passes a fixed string
  literal (`:66-116`, `:129`, `:193`, `:266`, `:273-275`); no table byte is
  echoed to the device. The canary therefore stays host-side only. This is a
  structural ceiling for this camlib, not disproof of a separate consumer or
  transport path. Grade unchanged: rung 4 author-side, rung 5 UNKNOWN.
  Source citations, disposition and the unchanged harness check
  (`PASS=146 FAIL=0`) are in
  `lab/frontier/libgphoto2shell/evidence/w176-closed-readback-lanes.out`.

- Real-API disclosure of the overflowed frame (W177, 2026-11-24): with the
  W175 canary-safe short reply and a device count of 1053 (still the W175
  16848-byte `:154` source over-read), `gp_camera_file_get(...,
  GP_FILE_TYPE_RAW)` reads `priv->table + 16*k` at `library.c:213` for
  filename numbers above 1024 — past the fixed 16384-byte table and into
  the stack bytes the `memmove` copied there. In three fresh processes the
  canary at k=1023 equalled the probe's own `%fs:0x28` value, and the two
  words at k=1024 (`info+0x4030/0x4038`, exactly the slots W167 overwrites)
  were a saved frame pointer and a code pointer that changed with ASLR.
  gdb in the same process showed those words byte-for-byte equal to the
  saved rbp/RIP at `jl2005c_init`'s caller slot. Further entries disclosed a
  second frame canary and the caller `rbx`/`rbp`/RIP that W171 obtains by
  gdb injection: k=1038's words matched `GDB_AT_R2` and `GDB_AT_R2_8`
  exactly. Controls: count 100 gives `rc=-108` (no entry); a full reply
  gives `*** stack smashing detected ***` before any file_get; count 1054
  needs more guard chunks and shows a tcache double-free on repeated
  reads. This means the W167/W171 author-side gdb *reads* could be replaced
  by real-API reads, but W176 still holds: the bytes return to a HOST
  consumer and no camlib `gp_port_write` echoes them to the device. No
  device-only canary recovery, no wire, no command, no witness verdict.
  Rung 4 author-side; rung 5 UNKNOWN. Evidence, probe and gdb map:
  `lab/frontier/libgphoto2shell/evidence/real-plain-stack-leak.out`,
  `replay-stack-leak-probe.c`, `replay-w177-map.gdb`.

- Clean-archive replay and release-tag check (W178, 2026-11-24): W177's
  real-library limb previously depended on four W175 vusb hunks that lived
  only in a throwaway tree. Those four hunks are now committed as
  `lab/frontier/libgphoto2shell/evidence/replay-vusb-shortreply.patch`, so
  W175/W177 replay from Git with the patch stack recorded in `REPLAY.md`.
  From a clean `git archive` of HEAD (`efe96160`): 121 files, 4/4 pin
  checksums, 12 harness binaries, `PASS=146 FAIL=0` with the unchanged
  trace; the plain 2.5.34 build from the provisioned release tarball
  reproduced the three canary records, the three saved rbp/RIP records and
  the gdb byte-for-byte map, with the same safe-count and full-reply
  controls. This is the author's replay of an unwitnessed rung-4 scope, not
  independent acceptance and not a device-readback path; W176 still holds.
  Separately, at 23:01Z `git ls-remote --tags --refs
  https://github.com/gphoto/libgphoto2.git` still showed `v2.5.34`
  (`a4ec9cc8b799d3e620c89feeaeb3ec86f362a12f`) as the newest release tag,
  so the numeric fixed version stays UNKNOWN as of that observation.
  Evidence: `evidence/real-plain-stack-leak-clean-replay.out`.

- One-command clean-archive replay (W180, 2026-11-25): the W175/W177 real-API
  disclosure limb is now `lab/frontier/libgphoto2shell/live/replay-real-w177.sh`:
  from a clean `git archive` it verifies the pinned release tarball and 4/4
  source pins, applies the five committed vusb patches, builds the plain
  2.5.34 library, compiles the committed probe and checks nine cases. The
  heap-drain value is selected at run time because a fixed value is layout
  sensitive (28 corrupted the top chunk in two fresh trees, 30 failed in a
  third; 20 worked in the final tree); the criterion is the victim chunk at
  `priv+0x4050`, not the number. Observed from a clean archive of commit
  `97c61c79`: `RESULT: 20 PASS / 0 FAIL`, three canary records at k=1023,
  three saved-rbp/RIP records at k=1024, a read-only gdb match, a `rc=-108`
  count-100 control and a stack-smashing full-reply control. The failed fixed
  drain runs are preserved rather than erased. This is an author replay of
  an unwitnessed rung-4 scope; the disclosure still goes to a HOST consumer
  through `gp_camera_file_get()`, W176 still holds, and rung 5 stays UNKNOWN.
  Evidence: `evidence/real-plain-w180-one-command.out`, `REPLAY.md`.

- Natural consumer-pointer lane closed at source level (W181, 2026-11-25):
  of the two remaining lanes in the W180 wall, the "real consumer steers a
  chosen pointer without the probe supplying the address" lane has no
  in-struct path in v2.5.34. `pins/jl2005c.h.vuln:31-44` puts `table` last
  (offset 0x40, struct 0x4040 bytes); the only struct pointer, `data_cache`
  (`:40`), precedes it and the pinned `:154` memmove writes forward. Real
  consumers treat table bytes as data: `library.c:197-213` builds h/w,
  size and start offset from them and copies 16 bytes into a library
  `malloc`; `library.c:338-341` hands that malloc to
  `gp_file_set_data_and_size`, whose pointer assignment is at
  `gphoto2-file.c:315-325`. `gp_filesystem_number`
  (`gphoto2-filesys.c:1365-1400`) returns only non-negative indices, so
  W177's saved rbp/RIP words are consumer DATA, not dereferenced pointers.
  A pointer in a HEAP NEIGHBOUR of `priv` remains theoretically possible
  but was NOT measured here: W168's outside-grooming layouts failed and
  W170-W172 needed a probe-supplied address. Grade unchanged: author-side
  unwitnessed rung 4, rung 5 UNKNOWN; no new witness ask, no re-send.
  Citations and disposition:
  `lab/frontier/libgphoto2shell/evidence/w181-consumer-pointer-lane.out`.

- Natural heap-neighbour pointer lane closed on the measured real build
  (W182, 2026-11-25): with the W180 plain 2.5.34 replay tree and no lab
  drain/guard objects, the 464-byte `:154` destination window past `priv`
  contains no live allocation or pointer at the write moment; gdb at real
  `jl2005c.c:154` shows 56 zero qwords at `priv+0x4050`, and the chunk
  immediately after `priv` is the top chunk (size `0x14cb1` at
  `priv+0x4048`). The first objects carved from that window are 15
  `malloc(11)` filename strings allocated after `jl2005c_init` returns,
  which reinitialize it. With the lab `GUARDS=4/DRAIN=20` layout the window
  instead holds two zeroed `malloc(0x180)` drain/guard buffers from
  `gp_port_read`/vusb, again with no pointer. COUNT=1053 in the natural
  layout overwrites the top size and aborts in `malloc(): corrupted top
  size`; COUNT=100 is clean. So device bytes can corrupt allocator
  metadata, but a pointer still needs a probe-supplied address or a
  lab-placed victim (W170-W172), consistent with W168's grooming failures.
  Closed for this build/config only, not all allocator states; grade and
  rung 5 UNKNOWN unchanged. Evidence:
  `lab/frontier/libgphoto2shell/evidence/w182-natural-heap-ceiling.out`.

- Stack-argument-spill lane closed on the measured real builds (W185,
  2026-11-25): the remaining device-only pointer idea was that the `:152`
  forward write could reach a spilled `priv` pointer and turn `:154` into a
  write-what-where with a pointer chosen by the device. Disassembly of the
  exact lab `jl2005c.so` builds shows the opposite ordering: in the plain
  build `info` is `rbp-0x4030..-0x11` while `camera`/`port`/`priv` are spilled
  at `rbp-0x4058/-0x4060/-0x4068`, with `camera_id` and the other non-buffer
  locals also below `info`; the canary (`rbp-8`), saved rbp/RIP (`rbp+0/+8`)
  and caller frames are above it. The `:152` write starts at
  `rbp-0x3E30` and runs to `rbp+0x1CF` at count 1022 (or `rbp+0xFC1D0` at
  0xffff), so no argument slot is reachable. The ASan build has the same
  ordering (`priv` at `rbp-0x41e8`, `info` base `rbp-0x41c0`). `priv` is
  reloaded from its slot on each use, so this is a genuine write-what-where
  primitive if reachable — it is not, on these builds. The pin-based harness
  differs (its argument slots are above the buffer) but it uses stubbed
  plumbing. Combined with W181 (in-struct consumer bytes) and W182 (heap
  neighbour), all three natural-pointer variants are closed at measured
  scopes; no device-only pointer chain, command or rung 5. Evidence:
  `lab/frontier/libgphoto2shell/evidence/w185-stack-arg-spill-lane.out`.

- Compiler-dependent reopening of W185 (W190, 2026-11-25): W185's negative
  was measured on gcc builds only. The exact vulnerable TU compiled with
  clang 18 at the same plain flags puts `info` at `rbp-0x4050..-0x31`, spills
  `priv`/`port`/`camera` at `rbp-0x20/-0x18/-0x10`, and emits NO stack
  canary (`0` `%fs:0x28` references in 455 disassembly lines). Bulk offsets
  `0x3E30`/`0x3E38`/`0x3E40` therefore reach the three pointer slots;
  saved RBP and saved RIP are at bulk `0x3E50` and `0x3E58`. A full clean-tarball
  2.5.34 build with
  `CC=clang`, the committed vusb patch and the committed `p`-mode patch
  confirms the installed camlib has the same frame; at real
  `jl2005c.c:154` the destination is the `priv` slot reloaded from
  `rbp-0x20` plus `0x40`, source `rbp-0x4020`.

  With the existing `M2SHELL_JL2005_TOP` device reply setting that slot to a
  chosen address, the real `memmove` writes 15920 device-chosen `0x5a`
  bytes into a lab probe's global sink while `gp_camera_init` returns
  `rc=0`. No gdb injection and no host-supplied canary are involved; the
  only lab-assisted parts are the vusb device model and the probe's
  fixed-address sink (`-no-pie`). Shifting `DEV_TOP` by `0x40` shifts the
  first written byte by exactly `0x40` (`FIRST_5A` 576 -> 640), so the
  destination follows the device-supplied pointer. Safe count 100 and the
  upstream-fixed camlib leave the sink at its `0x11` fill with no `0x5a`
  bytes. This is a DEVICE-ONLY write-what-where at a real API in the clang
  build; W181/W182 remain closed for the gcc builds they measured, and
  W185 is now known to be compiler-specific, not a general ceiling.

  Grade unchanged at author-side rung 4, unwitnessed: the bytes go to a
  lab-chosen address (an attacker would need a known writable target), the
  transport is the synthetic vusb port, there is no wire/USB path, no
  control-flow target, no command and no rung 5. Evidence, build recipe,
  probe and controls:
  `lab/frontier/libgphoto2shell/evidence/w190-clang-arg-spill.out` and
  `evidence/replay-clang-wwhere-probe.c`.

- Chosen control-flow target on a canary-free clang build (W191,
  2026-11-25): the W190 frame has no stack protector and the oversized `:152`
  reply reaches both the spilled `priv` pointer (reply offset `0x3E30` ->
  `rbp-0x20`) and `jl2005c_init`'s saved RIP (`rbp+8`, reply offset
  `0x3E58`), measured with gdb at the installed `:154` memmove. A lab-only
  vusb `RET` knob writes device bytes at that offset; from a full clean clang
  2.5.34 build, a reply with count 1022 set the saved RIP to a probe function,
  which printed `M2SHELL_W191_BENIGN_MARKER` and exited 42 through
  `gp_camera_init`. The same reply also redirected the real `:154` memmove
  into the probe's sink. Controls: reply without `RET` faults at `rc=139`
  with `0x5a...` in saved RIP; count 100 and the upstream-fixed camlib do not
  execute the marker; reversing the fix restores it. No gdb injection,
  canary disclosure or host-supplied canary is involved, but the target
  address comes from the host environment and the transport is synthetic
  vusb — author-side rung 4 only, unwitnessed, no command and no wire, so
  rung 5 stays UNKNOWN. Evidence, patch and probe:
  `lab/frontier/libgphoto2shell/evidence/w191-control-flow.out`,
  `replay-vusb-ret.patch`, `replay-clang-control-flow-probe.c`.

- One-command clean-archive replay (W192, 2026-11-25): W191's chosen saved-RIP
  result is now replayable with
  `sh lab/frontier/libgphoto2shell/live/replay-clang-control-flow.sh` from a
  clean `git archive`, given the pinned 2.5.34 tarball (`TARBALL=/path`, sha256
  `5df9e774…7f28`). The script checks 4/4 pins, applies the three committed
  vusb patches, builds the full clang 18 library, compiles the probe, derives
  the marker and sink addresses from the safe count-100 run, then checks the
  attack, the no-`RET` fault, the upstream-fixed camlib and the fix reversal.
  Author in-tree run and a second run from a clean `git archive f1459319`
  (tarball supplied externally, 4/4 pins OK) both gave 12 PASS / 0 FAIL;
  exact addresses and all raw output in
  `lab/frontier/libgphoto2shell/evidence/w192-control-flow-replay.out` and
  `evidence/w192-clean-archive.out`. The compiled camlib hash differs between
  the two builds because the debug build embeds its source path, not because
  of a source change. This makes the replay self-contained but changes no
  grade: still author-side rung 4, unwitnessed, lab-assisted, synthetic vusb,
  no wire or command, rung 5 UNKNOWN.

- Address-independent partial pointer overwrite (W193, 2026-11-25): the W190
  clang frame puts the spilled `priv` pointer at bulk offset `0x3E30`. A new
  lab-only vusb mode caps the reply at `0x3E32` and changes only the low two
  bytes of that slot; port, camera, saved RBP and saved RIP remain live. Eight
  ASLR-on samples put `priv` at `...?600`, so the 16 fixed values
  `0x0430 + n*0x1000` cover one matching four-bit heap guess without an
  absolute address. A fork sweep gives all candidates the same inherited
  ASLR and heap layout; exactly one child hit. On a match the slot becomes
  `priv-0x1d0`; the real `:154` memmove starts at `priv-0x190` and ends at
  `priv+0x4040`, exactly the end of the original user allocation. gdb
  measured original `0x555555567600`, slot `0x555555567430`, destination
  `0x555555567470` and live saved RIP `0x7ffff7c277f3`. `gp_camera_init`
  returned 0 and direct table readback began `57 31 39 33` (`W193`).

  The direct probe deliberately performs no allocation after the corrupted
  heap. An earlier real file-get attempt succeeded once with tree-specific
  allocator metadata bytes, but the clean replay showed those values are not
  portable and aborted at the next malloc; that consumer result is NOT
  counted. The durable ASLR-on result is the normal init return plus chosen
  private fields/table bytes at a device-chosen relative offset. This is a
  4-bit ASLR guess, not an absolute target, physical/wire USB, command,
  witness verdict or rung 5. Replay:
  `lab/frontier/libgphoto2shell/live/replay-partial-priv.sh`,
  `evidence/replay-vusb-partial-priv.patch`,
  `evidence/replay-partial-priv-probe.c`, and
  `evidence/w193-partial-priv-replay.out`. Grade remains author-side rung 4,
  unwitnessed and synthetic-vusb-only; rung 5 UNKNOWN.

- Real consumer after the partial-pointer overwrite (W194, 2026-11-25): on the
  W193 clang build with ASLR off and the matching four-bit guess, the first
  malloc after `gp_camera_init` aborts with `malloc(): invalid next size
  (unsorted)`. gdb locates the unsorted victim at `priv-0x210` (size `0x3ab0`)
  and its next-chunk size word at `priv-0x58`; the W193 `:154` write zeroes
  that word and `priv`'s own chunk size at `priv-8`. A lab-only vusb knob then
  has the device reply supply three constant glibc size words (nextchunk size
  `0x40`, nextchunk `prev_size` `0x3ab0`, priv size `0x4051`). With those words
  the full real chain succeeds: `gp_camera_init rc=0`, one listed file
  (`jl_001.ppm`), `gp_camera_file_get(GP_FILE_TYPE_RAW) rc=0` with 528 bytes
  beginning `57 31 39 33 5a 5a 00 01`, and `gp_file_save rc=0` writing those
  device-chosen bytes to a host file. Controls: the same corruption without
  the header words aborts at `malloc(): invalid next size (unsorted)`; a
  wrong four-bit candidate under ASLR off also aborts at `malloc()`; count 100
  has no device marker. An ASLR-on sample with the same nibble guess also hit
  by the expected one-in-sixteen chance and is preserved separately, not used
  as a control. The three words are constants measured on this build's heap,
  not live addresses and not device-observable, and the transport is synthetic
  vusb: this shows the consumer failure is metadata consistency, not a
  structural barrier, but it is lab-assisted rung 4 only, unwitnessed, with no
  command, physical/wire USB or rung 5. Replay exits 0 with 13 PASS / 0 FAIL.
  Replay: `lab/frontier/libgphoto2shell/live/replay-w194-file-consumer.sh`,
  `evidence/replay-vusb-heap-header-repair.patch`,
  `evidence/replay-file-consumer-probe.c`,
  `evidence/w194-file-consumer.out`.

  Clean-archive counterexample (same wake): rebuilding the W193 base from
  commit `ddb8785f` in a fresh `/tmp` tree put `priv` at `...?620`, so W193's
  fixed 16-candidate sweep (all ending `0x430`) had no hit and its replay
  ended 14 PASS / 2 FAIL; only the gdb-derived `0x7450` matched. Running W194
  in that clean tree with the derived candidate and the same three repair
  constants aborted at `corrupted size vs. prev_size` in both attack and
  no-repair cases (5 PASS / 8 FAIL), with no consumer write. The three words
  are therefore tree-specific, not a device-recoverable value: the consumer
  lane remains closed without host-derived allocator metadata. Raw:
  `evidence/w193-clean-base-sweep-negative.out`,
  `evidence/w194-clean-archive-negative.out`.

- Device-only natural heap overflow is blocked by a coupled header/pointer
  slot (W195, 2026-11-25, negative on the W193 clang build): vusb mode `s`
  stops the bulk reply at `0x3E20`, before clang's spilled `priv` pointer
  (`info+0x4030`, reply `0x3E30`), so `:154` keeps the real `priv->table`
  destination with no host address, canary or W194 repair words. `gp_camera_init`
  still returns 0 at count 1022, but the first consumer allocation aborts at
  `malloc(): corrupted top size`. gdb at `jl2005c.c:155` measures the safe
  count's top header at `priv+0x4040/0x4048` (prev_size 0, size `0xe9c1`);
  the copy maps table offsets `0x4000/0x4008` to reply `0x3E30/0x3E38`, so
  the bytes that would restore the top size necessarily overwrite the only
  spilled copy of the live `priv` pointer. A causal control (mode `n`) with a
  gdb-derived full pointer `0x555555567600` at `0x3E30` and the constant
  `0xe9c1` at `0x3E38` reaches `gp_camera_folder_list_files rc=0 count=1022`;
  a wrong top size aborts in `sysmalloc`, and the fixed camlib reduces the
  bulk request from 16384 to 512 bytes (its `jl2005c_init` error is not
  propagated by `camera_init`, so `gp_camera_init` still prints rc=0). No
  device-only layout on this build survives the consumer; the host-supplied
  pointer keeps this at lab-assisted rung 4, unwitnessed, rung 5 UNKNOWN.
  Replay: `lab/frontier/libgphoto2shell/live/replay-w195-device-only-negative.sh`
  (9 PASS / 0 FAIL), `evidence/w195-device-only-negative.out`,
  `evidence/w195-top-header-map.out`,
  `evidence/w195-vusb-natural-repair.patch`.

- GCC no-canary layout does not reopen the device-only lane (W196,
  2026-11-25, negative): a GCC 2.5.34 build of the pinned tree with
  `-fno-stack-protector` was driven with the same real `gp_camera_init()` /
  vusb consumer probe. gdb at `jl2005c.c:155` with count 100 measured the
  top header at `priv+0x4040/0x4048` (prev_size 0, size `0x12bb1`). Count
  1022 with the reply capped at `0x3E20` still gives init rc=0 and then
  `malloc(): corrupted top size` (rc 134); count 100 lists 100 files.
  Supplying `M2SHELL_W195_PRIV=0` (a device constant, not a live address)
  and the measured top size faults inside `memmove` at `:154` (rc 139),
  with the destination shifted to `priv+0x4070` and the saved RIP equal to
  `0x12bb1` — reply offset `0x3E38` is both the top-size source and the
  saved-RIP slot here as well. A lab-only sweep of 16 low-16-bit pointer
  candidates with the device-constant top size gave 16/16 SIGSEGV in
  `memmove` and no consumer listing. No device-only top-header repair is
  observed on either compiler; the W195 coupling is not clang-specific.
  Grade unchanged: author-side rung 4, unwitnessed, no wire, command or
  physical USB path, rung 5 UNKNOWN. Raw output (build, gdb map, controls
  and sweep): `lab/frontier/libgphoto2shell/evidence/w196-gcc-device-only.out`.
