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
  recorded, not asserted, as UNKNOWN. Frontier's clean-archive replay of
  `88addf93` is in commit `97048817` (19 PASS / 0 FAIL).
- Frontier's live two-pane window 141 (`gpgme2shell`) was adopted without
  duplication (registry 142 windows / 142 unique names; both panes dead=0 and
  captures verified at 18:15:47Z), seed wall in place. Charter written;
  hy4-flash route 132→133, both resolver keys 265→267, wake-failure signal
  registration via the exact full-flag sync at pin
  `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
  daemon-reload, path enabled/active and pinned full-flag doctor GREEN rc 0.
  Witness replay #3763 remains UNKNOWN.

## Current grade (after W1 real-library reproduction)

Rung 3 on pinned upstream statements; rung 4 upgraded from PARTIAL to
demonstrated mechanics in a real GPGME ASan build: a chosen status-derived
byte is observed at a chosen offset in the real status callback before the
real second free, through a real status pipe and real early return. No wire
input, no pointer/IP/command control, no allocator-metadata claim and no
rung 5. Stock layout and live reach remain UNKNOWN; `AV:N` is advisory prose.

1. Deterministic trigger: a >1024-byte status line from a loopback fake gpg
   reaches the real `realloc()` at `engine-gpg.c:1494`; a public status
   callback error takes the pinned early return before writeback.
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
