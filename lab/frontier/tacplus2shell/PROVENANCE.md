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

W122 grooming probe (negative results, see
`reports/tacplus2shell-status.md`): `harness/gdb-groom.cmd` adds gdb
breakpoints/dumps for the prime and trigger buffers, `harness/wire2.py` sends
prime+trigger on one connection, `harness/wire3.py` primes with a large
AUTHEN START and triggers AUTHOR on seq 3, and `harness/run_gdb2.py` drives
either client under gdb (`--client wire2.py|wire3.py`). All remain loopback
only; their `gdb-groom*.log` / `gdb-sameconn*.log` / `gdb-authprime*.log`
output is local-only evidence.

W127 cross-packet readback (plain vulnerable/fixed trees above, no rebuild):
`harness/wire4.py` sends a seq-3 large AUTHEN/CONT prime with a chosen
`cmd=`-pattern payload and a seq-1 AUTHOR trigger in a new session on the same
loopback connection; `harness/gdb-reuse.cmd` records the prime and trigger
buffer addresses, the surviving prime plaintext and each `eval_args()` copy;
`harness/run_gdb2.py --client wire4.py --client-args=...` drives either case
(the `--client-args` passthrough was added in W127);
`harness/run_reuse.sh` runs vulnerable/fixed/no-prime/alternate-pattern cases
and records normalized hashes in `harness/reuse-r1.txt` / `-r2.txt`. Raw
`harness/reuse-*.log` and `reuse-*.stdout` are local-only evidence. Details in
`reports/tacplus2shell-status.md` section "W127 cross-packet chosen-byte
readback at live-daemon scope".

W128 stack-overflow probe (same plain trees, no rebuild): `wire4.py
--skips 8,9,10,11,12` makes table index 12 a 255-byte OOB `cmd=` argument that
reads W127's surviving prime pattern; `harness/gdb-overflow.cmd` records the
pre-copy frame/locals, the 251-byte copy, the overwritten saved RBP/RIP and the
fault at `author.c:92`. `harness/run_overflow.sh` runs vulnerable/fixed/
no-prime cases and records normalized hashes in `harness/overflow-r1.txt` /
`-r2.txt`; raw `harness/overflow-*.log` and `overflow-*.stdout` are local-only
evidence. Details in `reports/tacplus2shell-status.md` section "W128
chosen-byte overflow of the live daemon stack".

W129 write-what-where probe (same plain trees, no rebuild): `harness/wire5.py`
carries three chosen records in the surviving prime plaintext at `in+1156` so
the 136-byte transit copy restores the saved `cmdline` pointer and loop counter
in `eval_args()`'s frame, the next 8-byte copy replaces the `t` cursor, and a
final copy writes chosen bytes plus NUL at the resulting address. `harness/
gdb-ptr.cmd` records the frame slots, the redirected target and the before/
after bytes; `harness/run_ptr.sh` runs vulnerable/fixed/no-prime cases with
normalized hashes in `harness/ptr-r1.txt` / `-r2.txt`. Raw `ptr-*.log` and
`ptr-*.stdout` are local-only evidence. `harness/wire6.py` with `gdb-rce.cmd`,
`gdb-measure.cmd` and `gdb-memdump.cmd` is the preserved negative rung-5 probe:
a fake `mem_t` destructor write reached the heap but aborted in adjacent glibc
metadata with no command side effect. Details in
`reports/tacplus2shell-status.md` section "W129 live-daemon write-what-where
via the t stack slot".

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
