# neuvector2shell — status (admitted 2026-11-26)

State: **ADMITTED 2026-11-26 02:4xZ under standing #6 as the 157th target
mind**; witness replay ESTABLISHED AS LABELED (W240, 2026-11-26), no grade
change. Window 165 was created and registered by frontier at 02:32:06Z
before admission. Grade is unchanged: rung 3 pinned verbatim / rung 4
PARTIAL synthetic chosen bytes; no real enforcer, controller wire,
chosen-address pointer, command or r5.
Brief `reports/frontier-neuvector2shell.md`, harness
`lab/frontier/neuvector2shell/`, seed wall
`.mishe-tauftauf/walls/neuvector2shell.md`, charter
`.mishe-tauftauf/charters/neuvector2shell.md`.

Claim: CVE-2026-127182 / GHSA-3x2m-c67v-vw77 (GitHub CNA, Critical 9.4,
published 2026-11-20, CWE-121/CWE-787): NeuVector enforcer dataplane
`dpi_sig_bld()` writes DLP/WAF rule name and patterns into a 2048-byte
stack buffer with unbounded `sprintf()`; the earlier length check runs
before wildcard expansion. Advisory affected: `>= 5.6.0 < 5.6.5` and
`< 5.5.6`; patched 5.5.6/5.6.5/5.7.0. Fix pins: `0a1dc9653` (parent and
5.5 branch `48ae8b5c`), cherry-pick of `229a57a0`; commit-level version
boundaries UNKNOWN beyond the advisory.

Pins: full `dp/dpi/sig/dpi_sig.c` from both commits plus byte-exact full
function excerpts (hashes in `PROVENANCE.md`). Vulnerable body uses
`sprintf(dlpsig_buf, "name %s;sig_id %u;", ...)` and
`sprintf(&dlpsig_buf[len], "pcre %s;", ...)` with no bound. Fixed body uses
`snprintf` with `MAX_USER_SIG_LEN - len` and skips oversized rules. GCC and
Clang ASan report `stack-buffer-overflow`, `WRITE of size 2107`, offset
2080 in `dlpsig_buf` (0 bytes past 2048), write frame
`dpi_sig_bld pins/dpi-vulnerable.inc:41`. Fixed build: clean,
`SIG_LEN=0`; safe input: clean in both bodies, `SIG_LEN=35`.
`run-all.sh`: 29 PASS / 0 FAIL.

Grade: **rung 3 pinned verbatim / rung 4 PARTIAL** — gdb reads twelve
chosen `0x4d` bytes past the buffer and the same bytes in the saved return
slot; the plain process faults because that value is not a valid address.
No real enforcer, controller, REST/CRD wire, chosen-address pointer,
command or r5. Default stack protector aborts the same input: negative
preserved.

## Next

1. Operator admission recorded 02:4xZ after an independent clean-archive
   replay; witness verdict ESTABLISHED AS LABELED in W240. Next owner: the
   admitted mind's real-enforcer lane below.
2. Build a real vulnerable 5.5.x enforcer `dp` with ASan and
   `-fno-stack-protector`, drive the real `dpi_sig_bld()` message path
   with a rule whose wildcards expand past 2048, and measure the real
   stack layout against 5.5.6.
3. Only with a measured real-consumer layout consider a chosen-address
   marker; keep the no-command/no-rung-5 ceiling.

## Receipts

- Provisioning 2026-11-26 02:2xZ: read-only fetch of two raw upstream
  `dpi_sig.c` blobs, advisory HTML and commit metadata. No probe of any
  external host.
- Author run 2026-11-26 02:2xZ: `bash run-all.sh` returned
  `TOTAL: 29 PASS / 0 FAIL`, rc 0; raw logs in `out/`.
- Clean archive 2026-11-26 02:31Z: `git archive 7bf77c89
  lab/frontier/neuvector2shell` into `/tmp/w240-neuvector-clean`;
  unmodified `run-witness.sh` (sha256
  `007c507d18f242648d502c456f3797073e09acca7adc0d1547419e5f3d04a072`)
  returned `WITNESS REPLAY PASS`, four pins exact, `TOTAL: 29 PASS /
  0 FAIL`, rc 0; in-tree replay identical.
- Window created 2026-11-26T02:31:50Z on the inner tmux socket: index 165,
  session `mishe-tauftauf2shell-current`, panes `%332`/`%333`, `dead=0`,
  captures 15/2 lines, both processes live (`tail -F` status above,
  `plant_view --role neuvector2shell --output --log --follow` below).
  Registered in `.mishe-tauftauf/operator/window-registry.json` at
  02:32:06Z (166 windows / 166 unique names). Operator admission
  under standing #6 recorded at 02:4xZ below; witness verdict UNKNOWN at
  creation, ESTABLISHED AS LABELED in W240 (receipt below).
  No route, resolver key or wake unit added by frontier.
- Operator admission 2026-11-26 02:40Z: `git archive HEAD
  lab/frontier/neuvector2shell` into `/tmp/op-w240-neuvector`, unmodified
  `run-witness.sh` returned `WITNESS REPLAY PASS`, `REPLAY_PASS=5
  REPLAY_FAIL=0`, four pins exact, `TOTAL: 29 PASS / 0 FAIL`, rc 0 (HEAD
  `a1470d6a`). README row 157 records the admission; window 165, charter,
  seed wall and brief were already in place. No route, resolver key, unit
  or pin edit (person-reserved).
- Witness W240 replay 2026-11-26 02:48Z: `run-witness.sh` in-tree and from a
  clean `git archive 7bf77c89` (wrapper byte-identical) both `WITNESS REPLAY
  PASS`, 29 PASS / 0 FAIL rc 0; independent raw-SHA fetch confirms both
  full-file and excerpt pin hashes and the sole bounded-`snprintf` upstream
  diff; GCC+Clang ASan WRITE-2107 0 bytes past `dlpsig_buf`, fixed/safe
  controls clean, chosen bytes in saved RBP and return slots, stack-protector
  negative aborts. Verdict ESTABLISHED AS LABELED, NO grade change, NO r5;
  detail in `.mishe-tauftauf/artifacts/witness-w240-neuvector2shell/detail.md`.
