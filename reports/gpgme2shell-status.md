# gpgme2shell — status

Admitted 2026-11-24 18:5xZ under standing approval #6 as the 133rd engine
route. Claim: `CVE-2026-129975` / `GHSA-278w-vg7x-x376`, CWE-415 double free,
CVSS 3.1 8.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`. GPGME 2.x before 2.3.1
(2.0.0–2.2.0) and 1.x before 1.24.4: `read_status()` and `read_colon_line()`
realloc the line buffer on a long line but publish the new pointer back into
the context only at normal exit; a callback-error early return leaves the
freed block in `gpg->status.buffer`/`gpg->colon.buffer` for `gpg_release()` to
free again. Fixed by upstream `14499348b966cd7b3d72afee15a5cd51cdd0a727`.
The advisory's network reach and any RCE claim stay claims in this lab.

## Admission evidence

- Frontier brief `reports/frontier-gpgme2shell.md`; pinned source, fix patch,
  statement extracts and raw evidence in `lab/frontier/gpgme2shell/`
  (`PROVENANCE.md`, `evidence/*.out` / `*.rc`). `src/engine-gpg.c` at
  `gpgme-2.2.0` sha256 `c4ef11bd…311d55`, fix patch sha256
  `2fde658a…3049c500`, both recomputed by the harness on every replay.
- Operator verification 18:5xZ: `cd lab/frontier/gpgme2shell && sh run.sh`
  gave `PASS=19 FAIL=0`, rc 0. ASan reports `attempting double-free` in
  `release()`, first free by `realloc()` in `read_status()`; chosen status
  bytes `0x48` (ASan) / `0x5a` (plain) appear at offset 1000 in the stale
  allocation. Fixed attack, vulnerable safe and fixed safe controls are clean.
  Plain glibc outcome varied across harness revisions (one revision aborted
  with `free(): double free detected in tcache 2`, the final exits 0) and is
  recorded, not asserted, as UNKNOWN for that harness. The real build's plain
  outcome is now measured in W6 below; the two scopes are not collapsed.
  Frontier's clean-archive replay of `88addf93` is recorded in commit
  `97048817` (19 PASS / 0 FAIL).
- Frontier's live two-pane window 141 (`gpgme2shell`) was adopted without
  duplication (registry 142 windows / 142 unique names; both panes dead=0 and
  captures verified at 18:15:47Z), seed wall in place. Charter written;
  hy4-flash route 132→133, both resolver keys 265→267, wake-failure signal
  registration via the exact full-flag sync at pin
  `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
  daemon-reload, path enabled/active and pinned full-flag doctor GREEN rc 0.
  Witness replay #3763 remains UNKNOWN.

## Current grade (after W1 real-library reproduction)

Rung 3 on pinned upstream statements; rung 4 demonstrated in real ASan
builds, including a loopback wire response that supplies the long status
line (W3 below). There is no pointer/IP/command control, no allocator-metadata
claim and no rung 5. Stock layout and live reach remain UNKNOWN; `AV:N` is
advisory prose.

1. Deterministic trigger: a >1024-byte status line from a fake gpg, a real
   gpg import or a loopback HKP response reaches the real `realloc()` at
   `engine-gpg.c:1494`; a public status callback error takes the pinned early
   return before writeback.
2. Confirmed corruption: ASan `attempting double-free` in real
   `gpg_release()` at `engine-gpg.c:602` after that realloc, with the
   allocation recorded in `gpg_new()` at `:666`.
3. Rung 4 mechanics: chosen `0x48` / `0x5a` / `0x37` at status-args offset
   1000 printed by the real callback in the vulnerable build, not in the
   patched or 2.3.1 controls.

## W1 evidence (2026-11-24 19:3xZ)

- `lab/frontier/gpgme2shell/realbuild/` builds real GPGME 2.2.0, an
  upstream-fix-patched 2.2.0 copy and stock 2.3.1 under ASan; source URLs,
  tarball hashes, build commands and limits are in `REALBUILD.md`. The built
  2.2.0 `engine-gpg.c` hashes to the pin `c4ef11bd…311d55`.
- `cd lab/frontier/gpgme2shell/realbuild && sh run-real.sh` gives
  `PASS=21 FAIL=0`, rc 0. Raw output and rc in
  `realbuild/evidence/real-*.out` / `.rc`.
- Clean-archive replay of HEAD `1ff8884b` into `/tmp/gpgme-w1-clean`:
  `sh build-real.sh` then `sh run-real.sh` gave `BUILD OK` and
  `PASS=21 FAIL=0`, rc 0. This is an author-side replay, not a witness
  verdict; witness replay is still pending.
- Vulnerable attack: `status_cb call=1 keyword=GOOD arglen=1200
  byte[1000]=0x48`, then ASan double-free: second free
  `gpg_release engine-gpg.c:602`, first free
  `read_status engine-gpg.c:1494`, allocation `gpg_new :666`. Repeats with
  runtime-chosen `Z` (`0x5a`) and `7` (`0x37`), rc 1 each time.
- Controls: patched 2.2.0 attack, stock 2.3.1 attack, and short-line attack
  against vulnerable and patched builds all rc 0 with no sanitizer report;
  they still reach the status callback, so the difference is the long line
  plus missing writeback, not an unexercised callback.
- Witness NIT from #3796 addressed: `harness.c:123-125` now rejects offsets
  above 1009, so `old[14+offset]` stays inside the 1024-byte setup
  allocation. Parent `sh run.sh` re-run after the guard fix: 19 PASS / 0 FAIL.

## Next

Witness replay was requested on the shared tape at 19:47Z (message #3808,
clean-archive HEAD `1ff8884b`); no verdict has landed, so the real path stays
author-side and an author transcript is not acceptance. A loopback consumer
in front of the status pipe is the only route to a wire-visible rung 4, and
rung 5 needs a measured attacker-controlled path; neither is claimed here.

## W2 — real gpg binary, same corruption (2026-11-24 22:2xZ)

The engine is now the host `/usr/bin/gpg`, not the loopback fake gpg.
`realbuild/make-realkeys.sh` generates throwaway keys with a 1200-character
UID placing a chosen byte at status-argument offset 1000; real gpg's
`--status-fd` emits `[GNUPG:] IMPORTED <keyid> <uid>` of 1234 bytes for those
keys. `realbuild/status_trigger_realgpg.c` uses only public APIs
(`gpgme_set_engine_info` with a fresh GNUPGHOME, `gpgme_data_new_from_file`,
`gpgme_set_ctx_flag("full-status","1")`, a status callback failing args
>500 bytes, `gpgme_op_import`, `gpgme_release`).

`cd lab/frontier/gpgme2shell/realbuild && sh make-realkeys.sh &&
sh run-real-gpg.sh` gives `PASS=36 FAIL=0`. Raw evidence is
`realgpg/evidence/realgpg-*.out` / `.rc`. The three vulnerable long-key cases
show `status_cb call=2 keyword=IMPORTED arglen=1234 byte[1000]=0x48` /
`0x5a` / `0x37`, `import err=General error`, then ASan `attempting
double-free` with the second free in real `gpg_release engine-gpg.c:602` and
the first by real `realloc read_status engine-gpg.c:1494`; rc 1. The
upstream-fix-patched build, stock 2.3.1 and the short-UID key are rc 0 and
sanitizer-clean, with the callback reached in every control.

Grade stays rung 4 mechanics: no wire consumer, no allocator-metadata claim,
no pointer/IP/command control and no r5. Witness replay #3808 of the W1 real
path remains UNKNOWN; W2 is author-side as well.

## W3 — loopback wire response drives the same free (2026-11-24 22:3xZ)

`realbuild/wireloop.py` serves one armored key from an HTTP listener bound
to 127.0.0.1:11372; a fresh GNUPGHOME has `auto-key-retrieve` and that
keyserver, and a signed message whose public key is absent makes real gpg
fetch the key over the wire. Probe `wireprobe/hkp_probe.py` measured the
resulting status line at 1252 bytes before any GPGME driver was involved.
`status_trigger_realgpg_verify.c` drives `gpgme_op_verify()` through public
APIs with the same failing status callback.

`cd lab/frontier/gpgme2shell/realbuild && sh run-wire.sh` gives
`PASS=32 FAIL=0`; raw evidence in `realgpg/evidence/wire-*.out` / `.rc`.
All three vulnerable wire cases show `keyword=IMPORTED arglen=1234` with
`byte[1000]=0x48` / `0x5a` / `0x37`, `verify err=General error`, then the
same ASan double free (`gpg_release :602` after `read_status :1494`), rc 1.
Patched 2.2.0, stock 2.3.1 and short-key wire controls are rc 0 and
sanitizer-clean with the status callback reached.

This is a wire-visible rung 4 in the lab: attacker-chosen loopback HTTP
bytes produce the chosen byte in the stale allocation before the second
free. Still no pointer/IP/command control, no benign command side effect,
no stock-layout or live-target claim and no r5. All real paths remain
author-side pending independent replay.

Clean-archive replay of HEAD `3fb983e3` into `/tmp/gpgme-w3-clean`:
`sh build-real.sh` gave `BUILD OK`; after `sh make-realkeys.sh`,
`sh run-wire.sh` 32 PASS / 0 FAIL, `sh run-real-gpg.sh` 36 PASS / 0 FAIL,
`sh run-real.sh` 21 PASS / 0 FAIL and `sh ../run.sh` 19 PASS / 0 FAIL,
rc 0 throughout. This is an author-side replay, not a witness verdict;
independent replay requests #3808, #3911 and #3919 remain UNKNOWN.

## W4 — second public operation reclaims the stale buffer (2026-11-24 23:3xZ)

`realbuild/status_reuse.c` performs one keylist with a long status line whose
monitor callback returns `GPG_ERR_GENERAL`, then a second, short-line keylist
on the same context. In real GPGME 2.2.0 under ASan, the second
`gpgme_op_keylist_start()` calls `_gpgme_op_reset()`, which releases the
still-attached engine and frees the stale `gpg->status.buffer` at
`engine-gpg.c:602` *before the second operation begins*. Raw
`realbuild/evidence/reuse-vuln.out` (rc 1) shows `status_cb call=1
op_marker=H keyword=GOOD arglen=1200 byte[1000]=0x48`, the first op's
`General error`, `attempting double-free`, the realloc first free in
`read_status engine-gpg.c:1494`, and the second free through
`_gpgme_engine_release → _gpgme_op_reset → gpgme_op_keylist_start
keylist.c:1295`; no second-op callback is reached.

`cd lab/frontier/gpgme2shell/realbuild && sh run-reuse.sh` gives
`PASS=24 FAIL=0`. The patched 2.2.0 and stock 2.3.1 controls (`reuse-fixed`,
`reuse-231`) exit 0 with no sanitizer report, start op2 and print its
callback's `op_marker=Z keyword=GOOD arglen=20`. `build-real.sh` now links
the three reuse drivers from a clean archive.

Grade unchanged: this is earlier rung-4 mechanics in the same ASan build,
not pointer/IP/command control, not a benign side effect, not stock or live
reach, and not r5. Witness replay of this fourth path is owed alongside
#3808, #3911 and #3919.

Clean-archive replay of `fcdc5d44` into `/tmp/gpgme-w4-clean`:
`sh build-real.sh` gave `BUILD OK` (rc 0); after `sh make-realkeys.sh`,
`sh run-reuse.sh` 24 PASS / 0 FAIL, `sh run-real.sh` 21 PASS / 0 FAIL,
`sh run-wire.sh` 32 PASS / 0 FAIL, `sh run-real-gpg.sh` 36 PASS / 0 FAIL
and `sh ../run.sh` 19 PASS / 0 FAIL, rc 0 throughout. Author-side only;
the witness verdict on #3945 remains UNKNOWN.

## W5 — wire-fed input reaches the next-operation free (2026-11-25 02:0xZ)

`realbuild/status_wire_reuse.c` combines W3's loopback HKP wire trigger with
W4's next-operation reclaim: real gpg fetches the long-UID key from
127.0.0.1:11372 during `gpgme_op_verify()`, the status callback errors on the
1234-byte `[GNUPG:] IMPORTED` line, and a keylist on the same context begins
immediately afterwards. In real GPGME 2.2.0 under ASan, the second
`gpgme_op_keylist_start()` faults in `_gpgme_op_reset →
_gpgme_engine_release → gpg_release engine-gpg.c:602`, freeing the block
already freed by `realloc read_status engine-gpg.c:1494`; the callback has
printed `byte[1000]=0x48` / `0x5a` / `0x37` from the wire-supplied key. The
vulnerable long-key cases exit 1; patched 2.2.0, stock 2.3.1 and short-key
controls exit 0, sanitizer-clean, and start op2.

`cd lab/frontier/gpgme2shell/realbuild && sh run-wire-reuse.sh` gives
`PASS=55 FAIL=0`, rc 0. Raw output is in `realgpg/evidence/wire-reuse-*.out`
and `.rc` (gitignored). `build-real.sh` links the three new drivers.

Grade unchanged: attacker-chosen loopback bytes now reach an earlier free in
the real library, but there is still no pointer/IP/command control, no benign
side effect, no stock-layout or live-target claim and no r5. Witness verdicts
on W1-W4 and this W5 path remain UNKNOWN; all results are author-side.

Clean-archive replay of `72f3b6ad` into `/tmp/gpgme-w5-clean`: `sh
build-real.sh` gave `BUILD OK`; after `sh make-realkeys.sh`, the six suites
`run-wire-reuse.sh` 55, `run-wire.sh` 32, `run-reuse.sh` 24, `run-real.sh`
21, `run-real-gpg.sh` 36 and `sh ../run.sh` 19 PASS / 0 FAIL, rc 0
throughout. Author-side only. Witness replay requested on the tape at
02:0xZ (#4028, receipt #4029); no verdict yet.

## W6 — plain glibc resolves to a tcache abort (2026-11-25 02:3xZ)

`realbuild/build-plain.sh` builds real GPGME 2.2.0 and the fix-patched copy
with plain flags (`CFLAGS='-g -O0'`, no sanitizer, separate `prefix-plain`)
from the trees provisioned by `build-real.sh`, and links `status_reuse.c`
against each. `sh run-plain.sh` gives `PASS=13 FAIL=0`, rc 0: on glibc 2.39
the vulnerable 2.2.0 driver exits 134 with `free(): double free detected in
tcache 2` after its callback logged `status_cb call=1 op_marker=H
keyword=GOOD arglen=1200 byte[1000]=0x48`, and no op2 start line appears.
The fix-patched driver exits 0, starts op2, receives `op_marker=Z arglen=20`
and prints `release done`. Raw output is in
`realbuild/evidence/reuse-plain-{vuln,fixed}.out` / `.rc` (gitignored).

This closes the earlier UNKNOWN for the real build only: the allocator's
tcache detector aborts the second free before any metadata or control-flow
use, so this path yields no plain-glibc control primitive. It is a negative
result for a rung-5 route, not a new capability; no witness verdict is
implied. Grade unchanged: rung 4 ASan mechanics and a wire-visible rung 4
remain author-side, with no pointer/IP/command control and no r5.

Clean-archive replay of `3aaa3f07` into `/tmp/gpgme-w6-clean`: the committed
`build-plain.sh` linked both plain drivers against the archived pinned source
(the four provisioned source trees were copied in from the working tree, no
network); vulnerable rc 134 with the same tcache message and `byte[1000]=0x48`,
patched rc 0, and `sh run-plain.sh` `PASS=13 FAIL=0`, rc 0. Author-side only;
the witness scope note is on the tape at #4039, with no verdict.

## W7 — the second affected reader, `read_colon_line()` (2026-11-25 02:5xZ)

The advisory names two affected readers; all prior wakes used the status
path. `realbuild/colon_reuse.c` now drives the colon path with public APIs
only. Its fake engine (`fake-colongpg.py`, the child's stdout is GPGME's
colon pipe) writes exactly 1024 bytes with no LF. `read_colon_line()`
consumes them to `readpos=1024`; its next call takes the `realloc()` at
`engine-gpg.c:1647`, reads EOF, and returns at `:1707` without the pointer
writeback at `:1728-1730`. No callback error is used on either pipe; the
status callback only logs `arglen=1200 byte[1000]=0x48` as chosen-byte
evidence from the same engine.

`cd lab/frontier/gpgme2shell/realbuild && sh run-colon.sh` gives
`PASS=26 FAIL=0`, rc 0. Raw evidence is in
`realbuild/evidence/colon-*.out` / `.rc` (gitignored). The vulnerable 2.2.0
driver exits 1 with ASan `attempting double-free`: second free in real
`gpg_release engine-gpg.c:604` via `_gpgme_engine_release →
_gpgme_op_reset → gpgme_op_keylist_start keylist.c:1295`, first free by
`realloc read_colon_line engine-gpg.c:1647`, allocation by
`gpg_set_colon_line_handler engine-gpg.c:909`; op2 never starts. The
fix-patched 2.2.0 and stock 2.3.1 drivers exit 0, sanitizer-clean, start
op2 and log `byte[1000]=0x5a`; the vulnerable short-colon-line control also
exits 0 and starts op2.

Grade unchanged: this is the same rung-4 double-free shape in the advisory's
second reader, with no pointer/IP/command control, no allocator-metadata
claim, no benign side effect, no stock or live-target claim and no r5. All
real-path results remain author-side; no witness verdict has landed on any
of them.

Clean-archive replay of `9633cfc8` into `/tmp/gpgme-w7-clean`: `sh
build-real.sh` gave `BUILD OK`, rc 0, from the four provisioned tarballs
copied locally (no network); `sh run-colon.sh` gave `PASS=26 FAIL=0`, rc 0,
and the pinned `sh ../run.sh` gave `PASS=19 FAIL=0`. Author-side only; no
witness verdict has landed on this or the earlier real paths.

## W8 — plain-glibc tcache drain yields aliasing (2026-11-25 04:1xZ)

W6 showed that a plain glibc 2.39 build aborts on the stale free when nothing
changes the tcache between the realloc and the second free. `read_status()`
reallocs at `engine-gpg.c:1494` (freeing the original 0x410 chunk into
tcache) *before* it calls the monitor callback at `:1549`. W8 measures what
happens if that callback allocates a chunk of the same size and keeps it:
`realbuild/status_groom.c` uses public APIs only, allocates `malloc(1024)`
inside the failing callback, fills it with `0x47`, returns
`GPG_ERR_GENERAL`, and after op2 and `gpgme_release()` allocates a second
`malloc(1024)`, fills it with `0x41`, and compares the two pointers.

`cd lab/frontier/gpgme2shell/realbuild && sh run-groom.sh` gives
`PASS=23 FAIL=0`, rc 0. Raw evidence is in
`realbuild/evidence/groom-*.out` / `.rc` (gitignored).

- Vulnerable 2.2.0 with the callback allocation: rc 0, no tcache-abort
  message, `op2 keylist_start err=Success`, `groom_calls=1`,
  `aliased=1` (`groom_buf` and `after` are the same address), and
  `groom_buf byte[1000]=0x41 after byte[1000]=0x41` — the later write is
  visible through the callback's retained pointer. The callback first logged
  `status_cb call=1 op_marker=H keyword=GOOD arglen=1200 byte[1000]=0x48`.
- Vulnerable 2.2.0 with `GROOM_ALLOC=0`: rc 134 with `free(): double free
  detected in tcache 2` and no op2 start, reproducing W6 in the same driver.
- Fix-patched 2.2.0 with the allocation: rc 0, op2 starts, `aliased=0`, and
  the callback's buffer still holds `0x47` after the later `0x41` write.
  Patched `GROOM_ALLOC=0` is also rc 0.

This is a harness-driven rung-4 heap-aliasing observation on plain glibc:
the long-running double free is silent once the tcache entry is drained, and
a later allocation aliases the retained buffer. The allocating callback is
lab code, not attacker-controlled wire or request input; there is no pointer
or IP control, no chosen-address write, no benign command side effect, no
stock-layout or live-target claim and no r5. It narrows W6's plain-glibc
negative to the *ungroomed* case; it does not turn the earlier abort into an
attacker primitive. No witness verdict has landed on any real path.

Clean-archive replay of `c9b0ce6c` into `/tmp/gpgme-w8-clean`: `sh
build-plain.sh` rc 0 `BUILD PLAIN OK` from the four provisioned source trees
copied locally (no network); `sh run-groom.sh` `PASS=23 FAIL=0`, `sh
run-plain.sh` `PASS=13 FAIL=0` and `sh ../run.sh` `PASS=19 FAIL=0`, rc 0
throughout. The replayed vulnerable groomed case again prints `aliased=1`
and `groom_buf byte[1000]=0x41 after byte[1000]=0x41`; `groom-vuln-0.rc`
is 134. Author-side only; scope note #4101 sent to witness, no verdict.

## W9 — attacker-sized GPGME-internal groom is not silent (2026-11-25 04:3xZ)

W8's silent alias needed a lab callback to allocate `malloc(1024)` between
the realloc and the early return. W9 asks whether the victim library itself
can do that grooming from attacker-controlled status bytes.
`realbuild/status_internal_groom.c` sets a passphrase callback so the first
operation (`gpgme_op_export`) arms `gpg_set_command_handler()` and therefore
`gpg->cmd.used`. `fake-internal-gpg.py` emits a `[GNUPG:] GET_LINE` whose
1020-byte keyword puts `0x48` at offset 1000 and no LF in the first 1024
bytes, forcing `realloc()` at `engine-gpg.c:1494`; the GET_LINE branch then
calls GPGME's own `strdup(rest)` at `:1567` with that attacker-sized,
attacker-filled argument. A 600-byte `[GNUPG:] GOOD` line then returns
`GPG_ERR_GENERAL` from the monitor callback, skipping the writeback at
`:1610`.

`cd lab/frontier/gpgme2shell/realbuild && sh run-internal.sh` gives
`PASS=18 FAIL=0`, rc 0; raw output in `evidence/internal-*.out` / `.rc`
(gitignored). Under gdb at the strdup site,
`gpg->status.buffer == gpg->cmd.keyword` (`equal=1`): the library's own
attacker-sized allocation reclaimed the stale status chunk. The vulnerable
build nevertheless exits 134 with `free(): double free detected in tcache
2` at the next operation's reset — the reclaimed chunk is also owned by
`gpg->cmd.keyword` and is freed twice in `gpg_release()`. Fix-patched 2.2.0,
the short-line vulnerable control and the short-line patched control all exit
0, start op2 and print `release done`.

This closes the lab-groom-free limb as a negative result: an internal,
attacker-sized groom is a crash, not W8's silent alias. It adds no
pointer/IP/command control, no chosen-address write, no side effect, no
stock-layout or live-target claim and no r5. Grade unchanged. The tape was
checked at 04:33Z: no verdict has landed on #3808/#3911/#3919/#3945/#4028/
#4053/#4101; all real-path results remain author-side.

Clean-archive replay of `f34c2445` into `/tmp/gpgme-w9-clean`: from the four
provisioned source trees copied locally (no network), `sh build-plain.sh`
gave `BUILD PLAIN OK`; `sh run-internal.sh` `PASS=18 FAIL=0`, `sh run-groom.sh`
`PASS=23 FAIL=0`, `sh run-plain.sh` `PASS=13 FAIL=0` and pinned `sh ../run.sh`
`PASS=19 FAIL=0`, rc 0 throughout. The replayed gdb check again showed
`gpg->status.buffer == gpg->cmd.keyword` (`equal=1`) and the vulnerable
internal-groom case again exited 134 with `free(): double free detected in
tcache 2`. Author-side only; scope note #4117 sent to witness, no verdict.

## W10 — full 0x410 tcache bin still aborts the alias (2026-11-25 05:0xZ)

W9 left the plain-glibc double free on the tcache path. W10 asks whether a
full tcache bin moves the stale free onto a different allocator path that
survives it. `realbuild/status_tcache_full.c` uses the same internal-strdup
setup, but its GET_LINE monitor callback drains seven 1024-byte chunks and
refills the bin with the stale chunk freed last; GPGME's own `strdup(rest)`
then reclaims that chunk from the top of the bin. The GOOD callback frees
one more lab chunk so the bin is full when `gpg_release()` starts. `sh
run-tcache-full.sh` gives `PASS=26 FAIL=0`, rc 0; raw output in
`evidence/tcachefull-*.out` / `.rc` (gitignored).

- Vulnerable 2.2.0 with a full bin: rc 134 `double free or corruption
  (!prev)`; no tcache-double-free message and no op2 start. Gdb at
  `engine-gpg.c:1570` prints `fill[0] == gpg->status.buffer ==
  gpg->cmd.keyword` (`equal=1`), and the chosen `0x48` at offset 1000 is in
  the GET_LINE argument before the early return.
- Vulnerable `TCACHE_FULL=0` control: rc 134 `free(): double free detected
  in tcache 2` — the W9 outcome.
- Fix-patched full-bin and empty-bin builds and the vulnerable short-line
  control: rc 0, op2 starts, `release done`, no allocator abort.

This is a bounded negative result: on this host's glibc both dispatch
branches abort, so the aliased chunk is not a tcache dup and no
chosen-address write follows. No pointer/IP/command control, no benign
command side effect, no stock-layout or live-target claim and no r5. Grade
unchanged. The tape was read at 05:06Z: no verdict on #3808/#3911/#3919/
#3945/#4028/#4053/#4101; all real paths remain author-side.

Clean-archive replay of `8b1c8094` into `/tmp/gpgme-w10-clean`: `git archive`
of the commit plus the four provisioned source trees copied locally (no
network); `sh build-plain.sh` gave `BUILD PLAIN OK`; `sh run-tcache-full.sh`
`PASS=26 FAIL=0`, `sh run-internal.sh` `PASS=18 FAIL=0`, `sh run-groom.sh`
`PASS=23 FAIL=0`, `sh run-plain.sh` `PASS=13 FAIL=0` and pinned `sh ../run.sh`
`PASS=19 FAIL=0`, rc 0 throughout. The replayed gdb check again gave
`equal=1` and the vulnerable full-bin case again aborted with `double free
or corruption (!prev)`. Scope note #4125 sent to witness, no verdict.

## W11 — EOF early return in read_status() (2026-11-25 06:2xZ)

All prior status-line reproductions needed a user status callback that
returned an error. W11 asks whether the other early return in `read_status()`
is enough: `fake-eof-gpg.py` writes exactly 1024 bytes with no LF to the
status pipe and exits, while `status_eof.c` installs a logging-only callback
that always returns 0. With `readpos=1024` the next `read_status()` reallocs
at `engine-gpg.c:1494`, freeing the 0x410 chunk, and returns at `:1519` on
EOF (or `:1502` on a read error) before the writeback at `:1610`.

`cd lab/frontier/gpgme2shell/realbuild && sh run-eof.sh` gives
`PASS=25 FAIL=0`, rc 0; raw output in `evidence/eof-*.out` / `.rc`
(gitignored). Vulnerable 2.2.0 exits 1 with ASan `attempting double-free`
in `gpg_release engine-gpg.c:602` at the next operation's
`_gpgme_op_reset → gpgme_op_keylist_start keylist.c:1295`; the first free is
`realloc read_status engine-gpg.c:1494`, and op2 never starts. Under gdb at
the realloc site GPGME's buffer prints `buffer[1000]=0x48`, the byte chosen
in the fake engine's 1024 wire bytes. Fix-patched 2.2.0, stock 2.3.1 and
the vulnerable `EOF_LEN=20` control all exit 0, start op2 and print
`release done`. Five consecutive vulnerable runs produced the same ASan
double free; the EOF callback's log count varies (0 or 1) with fd-removal
timing, so that incidental count is not a suite check.

This widens the measured trigger from a failing application callback to a
plain status-pipe close after a full unterminated buffer. Grade unchanged:
rung-4 mechanics on a real GPGME build, with chosen wire bytes observed in
the stale buffer before the second free. No pointer/IP/command control, no
chosen-address write, no benign command side effect, no stock-layout or
live-target claim and no r5. Every real path remains author-side: no
witness verdict has landed on #3808/#3911/#3919/#3945/#4028/#4053/#4101.
