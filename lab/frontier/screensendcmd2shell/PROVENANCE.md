# screensendcmd2shell — provenance and pins (W370, 2026-11-27)

## Claim and source pins

- CVE-2026-71409, CERT Polska, published 2026-11-26, CWE-120, CVSS 4.0 4.6
  (`AV:L/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:L/...`). Vendor post:
  https://cert.pl/en/posts/2026/11/CVE-2026-71409/
  CVE record: https://www.cve.org/CVERecord?id=CVE-2026-71409
  Debian OSV mirror: https://api.osv.dev/v1/vulns/DEBIAN-CVE-2026-71409
- Claim: unchecked `sprintf()` in `SendCmdMessage()` (`attacher.c`) appends
  attacker-controlled `STY` to the global `SocketPath[]`; long `HOME`/`SCREENDIR`
  plus `STY` overflows the global. All versions before 5.0.2 affected; fixed in
  5.0.2. Same post reports CVE-2026-71410 (`utf8_handle_comb()` UAF in
  `encoding.c`) and CVE-2026-71411 (hardcopy ruid/euid TOCTOU), both fixed in
  5.0.2. Neither is built here.
- GNU release tarballs, fetched read-only from https://ftp.gnu.org/gnu/screen/:
  - `src/screen-5.0.1.tar.gz` SHA-256
    `2dae36f4db379ffcd14b691596ba6ec18ac3a9e22bc47ac239789ab58409869d`.
  - `src/screen-5.0.2.tar.gz` SHA-256
    `ca9a2c7e240919bc7ac12124593ae4529bb4eb5f7349d8857829b7e3f0b3b332`.
  - `screen-5.0.3.tar.gz` (read-only sibling check, not built) SHA-256
    `941c98ffecdca4bff4bbd1cd6f08fbd18967353affc46521040a999dafbd39a2`.
- `src/fix.patch` is the exact `diff -u` hunk between the two pinned
  `attacher.c` files; its SHA-256 is in `SHA256SUMS`.

## Source-bound mechanism

- `screen.h:44` `MAXSTR 768`; `screen.c:107`
  `char SocketPath[MAXPATHLEN + 2]`, with `MAXPATHLEN == PATH_MAX == 4096` on
  this x86-64 glibc host, so the global holds 4098 bytes.
- `screen.c:685-688` takes `sty` from `getenv("STY")` when no `-S` and not
  multi-attach. `screen.c:950` calls `SendCmdMessage(sty, SocketMatch, argv,
  queryflag >= 0)` when `cmdflag` is set by `-X`/`-Q` and `argv` is nonempty.
- Vulnerable 5.0.1 `attacher.c:429-436` caps `sty` at `FILENAME_MAX` and
  `2 * MAXSTR - 1` (1535), then executes
  `sprintf(SocketPath + strlen(SocketPath), "/%s", sty)` with no remaining-space
  check. `SCREENDIR` is capped below `MAXPATHLEN - 1` at `screen.c:797`;
  `screen.c:828` copies it into `SocketPath`, leaving as little as three bytes
  free before the append.
- Fixed 5.0.2 `attacher.c:435-438` computes `used = strlen(SocketPath)`, rejects
  `used + 1 + strlen(sty) >= sizeof(SocketPath)` with
  `Panic(0, "Socket path too long.")`, and uses bounded `snprintf`.
- Same-CVE sibling: 5.0.2 also bounds `FindSocket()`'s
  `sprintf(SocketPath + sdirlen, "/%s", name)` at `socket.c:196`. The 5.0.3
  tarball applies the same guard to `SendCreateMsg()` at `socket.c:447-452`.
  Both are listed for the owning mind; neither is built in this stage.

## Harness and commands

- `harness/build.sh` verifies `SHA256SUMS`, then extracts each pinned tarball
  with `--strip-components=1` and builds three in-tree arms:
  `vuln-asan` (5.0.1, `-O1 -g -fsanitize=address`),
  `fixed-asan` (5.0.2, same flags), and `vuln-asanrec` (5.0.1 with
  `-fsanitize-recover=address`) for post-write GDB inspection.
- `harness/run-all.sh` creates a loopback-local directory tree whose absolute
  path is exactly 3899 bytes, then drives the **real** `screen -X echo hi`
  binary with `SCREENDIR` set to that directory:
  - vulnerable ASan with `STY` = 300 `C` bytes;
  - fixed ASan with the same input;
  - vulnerable ASan with safe `STY=ok`;
  - recover-ASan build under GDB with `STY` = 600 `C` bytes, examining
    `attach_tty_name_in_ns` at the breakpoint after the `sprintf`.
  No server, listener, wire request, shell, command or external host is used.
- Regenerate from the repository root:
  `cd lab/frontier/screensendcmd2shell && ./harness/build.sh && ./harness/run-all.sh`.
  The script checks input pins at start and both input and stable-evidence pins
  at exit; `RUN_ALL_OK 13 PASS / 0 FAIL` is the expected result. Static,
  path-independent observations are pinned in `evidence/SHA256SUMS`; volatile
  ASan/GDB logs with PIDs and addresses are gitignored `probe/*.raw`.

## Observed evidence

- Vulnerable 5.0.1 ASan, `STY` 300: `global-buffer-overflow`, `WRITE of size
  302`, 0 bytes after the 4098-byte `SocketPath`, 62 bytes before the real
  global `attach_tty_name_in_ns` (size 4096), stack
  `SendCmdMessage attacher.c:434` ← `main screen.c:950`.
- Fixed 5.0.2 ASan, same input: rc 1, `Socket path too long.`, no ASan report.
- Vulnerable ASan, `STY=ok`: no ASan report.
- Recover-ASan GDB, `STY` 600: `SOCKETPATH_LEN=4500`, `ATTACK_STY_LEN=600`;
  `attach_tty_name_in_ns` bytes at offsets 0, 16, 32, 48, 64, 100, 200, 239
  and 240 all read `0x43`, the chosen `STY` byte.
- `RUN_ALL_OK 13 PASS / 0 FAIL` on two consecutive runs.

## Scope limits

R1/R2/R3 confirmed on the real, unmodified `screen -X` client path. R4 is
**LIMITED**: chosen bytes land at chosen offsets in a real adjacent global of
the ASan lab build; no function pointer, callback, control-flow transfer,
shell or command was exercised, and the global ordering is toolchain-specific.
A plain non-PIE 5.0.1 build puts the same overflow in BSS padding, not a live
global — preserved as a negative. R5 is **NOT CLAIMED**; no loopback service,
wire input or command side effect exists here.

Compiler-dependence negative: `CC=clang ./harness/build.sh` built all three arms
and `run-all.sh` gave 11 PASS / 2 FAIL. Clang ASan still reports
`global-buffer-overflow` with `WRITE of size 302` and the same sink/caller
lines, but names no adjacent global; under Clang's recover build the
`attach_tty_name_in_ns` offsets stayed zero. The chosen-byte-in-real-global
observation is therefore GCC/layout-specific, not a portable primitive; the
R4 grade already says LIMITED. GCC arms were rebuilt afterwards and the pinned
evidence restored to `RUN_ALL_OK 13 PASS / 0 FAIL`.
