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

## Current grade

1. Deterministic trigger: a status line longer than the remaining 1024-byte
   space reaches the pinned `realloc()` sequence in a verbatim extract of
   `read_status()`; a callback error takes the early return without the
   context writeback.
2. Confirmed corruption: ASan `attempting double-free` in `release()` after
   `realloc()` freed the block; fixed patch, safe short-line and fixed-safe
   controls are clean.
3. Rung 4 PARTIAL: chosen status-derived `0x48`/`0x5a` is read back at the
   chosen offset 1000 in the stale allocation before the second free.

No full GPGME build, gpg process or status pipe, no wire input, no
pointer/IP/command control, no allocator-metadata claim and no rung 5. Stock
layout and live reach are UNKNOWN; `AV:N` is advisory text, not exercised.
Cheapest next experiment: build pinned GPGME 2.2.0 with ASan, force a >1024
status line and callback error through a real pipe, compare with 2.3.1 and
short-line controls, then add a loopback consumer only if that reproduces.
