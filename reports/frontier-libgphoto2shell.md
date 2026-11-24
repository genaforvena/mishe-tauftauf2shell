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
or wire, so rung 5 is still UNKNOWN.
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
  two already-tracked fixes.
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
