# pymupdfcallout2shell — provenance and pins (W354, 2026-11-27)

## Claim and pins

- CVE-2026-120752 / GHSA-4gw9-9rgm-rwfx; affected PyMuPDF >= 1.25.3, < 2.0.
- Vulnerable commit `c26130ccfc7e5d8f83a05092d959d4794c5105bb` (parent of the
  fix); fixed commit `d4298ead84ceeae1c9065c81cd9a275a1b092f5e`; release 2.0
  tag points at `b8904b27efa0c4e2258f0e46ab4498a6173ffa22`.
- Pinned source blobs fetched from GitHub raw at those commits:
  - `src/extra.i` vulnerable SHA256
    `38a6dfb417e6a3cdc3cc0686f86e7e3e81d646d8f71d18dd7727a37f659e3085`
  - `src/extra.i` fixed SHA256
    `3e1d9d2b25a2a79ab2a0de9b0469bad9c9e7f81c0505c0804ddce8fcf0b0918e`
  - fix patch SHA256
    `a53189065f59414814f3612333f13faf3d61c90a14a97244a83692ccb0104c3d`
  - `src/__init__.py` vulnerable SHA256
    `165c35234aef0cc2a48c11de7fc6dfab3d9eae3a47992620fbe2178593822b01`
- Runtime binaries: public PyPI wheels `pymupdf==1.28.2` and `pymupdf==2.0`,
  installed into local isolated venvs. Wheel file hashes are not pinned here;
  the executable identity is checked at runtime via `pymupdf.VersionBind`
  (`1.28.2` vulnerable, `2.0` fixed) and the wheel's own version metadata. A
  source-built ASan binary is NOT part of this stage.

## Sink and caller

`src/__init__.py:9811-9812` passes `len(callout)` unchecked;
`src/extra.i:787-796` stores `count` 8-byte `fz_point` values into `points[3]`.
The fix adds a `count > 3` runtime error before the loop. No lab edit touches
either pinned source file; they are kept as read-only reference blobs in
`src/`.

## Harness and commands

- `harness/repro.py` builds a callout list from binary32 bit patterns and calls
  the real `page.add_freetext_annot()` Python API. Same script runs in both
  venvs; only the interpreter changes.
- `harness/gdb-callout.cmd` sets a pending breakpoint on
  `_wrap_JM_set_annot_callout_line`, records the entry stack pointer and saved
  return address, then breaks just before the wrapper's register pops to dump
  the overwritten stack. It is read-only (break, print, `x`, `continue`).
- `harness/run-all.sh` provisions both venvs and runs five checks:
  vulnerable 3-point safe, vulnerable 8-point `0x43434343` crash,
  GDB chosen saved-RIP slot with preserved RBP, fixed 3-point safe, fixed
  100-point rejection. Replay result: `RUN_ALL_OK 5 PASS / 0 FAIL`.
- Volatile GDB output contains ASLR addresses; its stable tokens are checked
  by `run-all.sh` and the log is excluded from any SHA256SUMS pin set.

## Scope limits

The wheel path is a real Python API call but not a source build or a wire
request; the process is a local Python interpreter. The chosen target
`0x4343434343434343` is noncanonical, so the wrapper faults at `ret` without
executing it. No marker, shell, command or debugger memory write exists. Any
claim of control-flow transfer or rung 5 requires a canonical mapped target
and an observed side effect.
