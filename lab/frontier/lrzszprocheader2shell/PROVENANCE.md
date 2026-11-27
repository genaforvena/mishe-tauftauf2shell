# lrzszprocheader2shell — provenance and pins (W352, 2026-11-27)

## Claim and pins

- CVE-2026-105842 / GHSA-3cw3-cf87-8pwp; affected lrzsz `< 0.13.0`; fixed
  `0.13.0` `b18b579272fa94748388364014f22e20712288d4`.
- Vulnerable worktree `vuln/` HEAD `b1fc8a01e3a074f8462a29dca45ed7c8fd2ef665`
  (pre-fix parent); fixed worktree `fixed/` HEAD
  `b18b579272fa94748388364014f22e20712288d4`.
- Fix commit `f8caa7b1b1a3a1bb50cf08677b15be7b17c2956f` changes
  `src/lrz.c:1217-1220` from fixed-capacity `malloc(PATH_MAX*2)` + `strcpy`
  to `strdup(name_static)`.
- Both worktrees are from `src/` (`git clone https://github.com/UweOhse/lrzsz.git`).
  No external target was contacted; file/loopback-only lab.

## Build adaptations (lab-only, not part of the vulnerability)

- Host autoconf 2.71 vs upstream `AC_PREREQ([2.72])`: lowered to 2.71 in both
  worktrees' `configure.ac`.
- `AUTOPOINT=true autoreconf -fi` with host gettext 0.22; copied
  `/usr/share/gettext/config.rpath` to `config.rpath` and
  `/usr/share/gettext/po/Makefile.in.in` to `po/Makefile.in.in` in both trees.
- Configure with `CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1"`
  (fixed tree additionally `-Wno-error` for new compiler warnings).
- These changes affect only build plumbing. The pinned `src/lrz.c` sink bytes
  and the fix hunk are unmodified.

## Harness and commands

`harness/procheader-harness.c` includes the pinned `src/lrz.c` with
`#define main lrz_unused_main`, sets `protocol=ZM_ZMODEM`, and calls the real
static `procheader()` with a name of chosen length/fill. It allocates 64 bytes
of trailing padding after the name terminator because the live receiver's
header buffer has following bytes at `src/lrz.c:1087`. Link line (vulnerable):

```
cc -fsanitize=address -fno-omit-frame-pointer -g -O1 -DHAVE_CONFIG_H -DNFGVMIN \
  -DLOCALEDIR='"/usr/local/share/locale"' -I vuln -I vuln/src -I vuln/lib \
  harness/procheader-harness.c $(ls vuln/src/*.o | grep -vE '/(lrz|lsz)\.o$') \
  vuln/lib/libzmodem.a -o evidence/harness-vuln
```

Fixed harness compiles the fixed `lrz.c` first in the include path and links
fixed support objects (`canit,crctab,lsyslog,protname,rbsb,stats,timing,util,
zm,zperr,zreadline`) plus the unchanged `vuln/lib/libzmodem.a`.

## Observed arms

| arm | command | result |
| --- | --- | --- |
| vulnerable safe | `harness-vuln 16 67` | `rc=0 Pathname_len=16`, no ASan |
| vulnerable attack | `harness-vuln 12000 67` | ASan `WRITE of size 12001` in `strcpy` at `src/lrz.c:1220`, 0 bytes past 8192-byte region from `:1217`, rc 1 |
| fixed attack | `harness-fixed 12000 67` | no ASan, `rc=-1 Pathname_len=12000` (safe `strdup`, long path rejected) |
| fixed safe | `harness-fixed 16 67` | `rc=0 Pathname_len=16` |

Logs: `evidence/{vuln-safe,vuln-attack,fixed-attack,fixed-safe}.out`.
`SHA256SUMS` covers harness sources and the stable logs; `vuln-attack.out` is
excluded because its PID, ASLR addresses and binary build-id vary per run.
The clean-archive replay of commit `2de80271` reproduced `RUN_ALL_OK 5 PASS /
0 FAIL`; its differing ASan log had the same `WRITE of size 12001`, sink
`src/lrz.c:1220` and allocation `:1217`, and differed only in PID/addresses
and extraction path (plain tar SHA-256
`c291854491a9142c31fd33f3b0ab7f9c28c15ff0b62ddd7661173962fc6fad17`).
Build logs: `evidence/{harness-build,fixed-harness-build}.log`, `vuln/{configure,build,autoreconf}.log`, `fixed/{...}`.

## Negatives and open work

- No live ZMODEM wire replay yet: this is a pinned-sink harness, not a running
  `lrz` fed by a malicious sender. R4 scope is accordingly limited.
- No chosen-address write, marker execution, shell command or r5 claim.
- Fixed `checkpath` rejects the 12000-byte path; the safety observed there is
  the removal of the OOB store, not the acceptance of the long name.
