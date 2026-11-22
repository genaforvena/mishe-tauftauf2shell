# Provenance — tacplus2shell (CVE-2026-130875)

## Pins and source

Cloned `https://github.com/tacplus-ng/event-driven-servers.git` once into
`src/`, checked out vulnerable `929671c` there, and created `src/fixed/` as a
git worktree at `d8493e0`. Blob SHA256 for both pins' `packet.c` and `author.c`
are in `PIN_HASHES.txt`. The fix hunk (verified from `git show d8493e0`) adds
one pair of parentheses on `packet.c:523` and `:538`; `author.c` is unchanged.

## Builds

Both pins: `./configure --asan --minimum --prefix=<lab inst dir> tac_plus-ng
mavis && make -j4`, producing clang `-fsanitize=address -g -O0` binaries at
`src/build/<os>/tac_plus-ng/tac_plus-ng` and
`src/fixed/build/<os>/tac_plus-ng/tac_plus-ng`. Build logs:
`conf-vuln.log`, `build-vuln.log`, `conf-fixed.log`, `build-fixed.log`.
`--minimum` disables curl/TLS/SSL/crypto/ares/SCTP/zlib; PCRE2, crypt and PAM
remain. No system install was performed.

### Plain (non-ASan) builds for live-daemon gdb readback

The ASan trees above were copied to `src-plain/` (vulnerable `929671c`) and
`src-fixed-plain/` (fixed `d8493e0` worktree) and rebuilt in place with
`./configure --debug --minimum tac_plus-ng mavis && make -j4`, logs
`conf-plain.log` / `build-plain.log` and `conf-fixed-plain.log` /
`build-fixed-plain.log`. Both compile with `clang -O0 -g -ggdb -DDEBUG` and
no `-fsanitize`; binaries live at
`src-plain/build/<os>/tac_plus-ng/tac_plus-ng` and
`src-fixed-plain/build/<os>/tac_plus-ng/tac_plus-ng`. `harness/run_gdb_case.py`
launches those binaries under gdb with a plant-created 127.0.0.1 listener as
fd 0; `harness/gdb-author.cmd` contains the breakpoints and dumps;
`harness/run_gdb.sh` runs vulnerable/fixed/safe cases and reports normalized
hashes (`harness/gdb-r1.txt`, `-r2.txt`). Raw `harness/gdb-*.log` and
`gdb-*.stdout` are local-only replay output.

## Local artifacts (all under this directory)

- `harness/tac.cfg` — lab config: loopback listener at 127.0.0.1:4949, key
  `demo`, user `demo`, profile permitting `service=shell`.
- `harness/wire.py` — TACACS+ packet builder and wire client. Uses the pinned
  `md5_xor()` pad exactly: `MD5(session_id || key || version || seq)`, then
  `MD5(session_id || key || version || seq || previous_pad)` per 16-byte block.
- `harness/run_case.py` — starts one daemon inetd-style with a plant-created
  127.0.0.1 listening socket passed as fd 0, runs the client, captures stderr,
  terminates the daemon. No wildcard bind, no external address.
- `harness/run_wire.sh` — real-daemon cases: vulnerable + crafted AUTHOR,
  fixed + same packet, vulnerable + safe packet. Normalized hashes in
  `harness/wire-r1.txt` / `harness/wire-r2.txt`; raw logs `w-vuln.log`,
  `w-fixed.log`, `w-safe.log`.
- `harness/gen.py` — extracts `author_pak_looks_bogus()`,
  `accounting_pak_looks_bogus()` and `eval_args()` byte-for-byte from the pinned
  blobs into `fn.inc`.
- `harness/harness.c` — minimal structs/macros and allocation stubs around the
  verbatim functions; places chosen bytes past the accepted packet in the heap
  and prints `cmdline`.
- `harness/run.sh` — gcc/clang, plain/ASan, both pins, two chosen bases,
  oversized-copy case. Replay logs `harness/harness-r1.txt` / `-r2.txt`.

## Non-local claims (not reproduced here)

The advisory's five-connection chain, heap pointer leak, libc leak,
session-pointer redirect, fake `mem_t` and `system()` call yielding root are
claim-source text only. Frontier observed no pointer control, command or side
effect beyond an ASan report and chosen bytes in a harness.
