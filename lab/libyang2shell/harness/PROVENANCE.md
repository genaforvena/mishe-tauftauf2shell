# Provenance — libyang2shell real `lyd_parse_data()` reproduction

## Source pins

Provisioned read-only from GitHub (`git clone`, no probing of external systems):

- Vulnerable: `979f6925cf1f0918915613022e9e9dfc751bf647` —
  `git -C src/libyang checkout 979f6925...`
- Hardened: `48672b289e2e4c6773712c3ee0abae6b7fffe1f3` —
  `git -C src/libyang worktree add ../libyang-hardened 48672b28...`
  (the worktree helper fell back to a plain checkout: FICLONE unsupported;
  `git rev-parse HEAD` confirmed the exact pin).
- Partial-fix pin `73da1db8fc14802e4f8fc64d022011a6f9d514db` is recorded in the
  frontier harness but not exercised here: its 4 GiB allocation would exceed a
  useful bounded wake.

Source hashes of the four verbatim frontier slices are in
`../../frontier/libyang2shell/harness/evidence/r1-pin-hashes.txt`.

## Consumer-source provenance (negative result)

- `src/consumer-libnetconf2`: `git clone --depth 1
  https://github.com/CESNET/libnetconf2.git` (HEAD at fetch time; a shallow
  snapshot, not a pin).
- `src/consumer-sysrepo`: `git clone --depth 1
  https://github.com/sysrepo/sysrepo.git` (same).
  These were read only to locate LYB parse entry points; no consumer was built
  or started.

## Builds

Both pins configured and built with:

```
cmake -S <src> -B <src>/build-asan -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=OFF \
  -DENABLE_VALGRIND_TESTS=OFF \
  -DCMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O1' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address'
cmake --build <src>/build-asan -j4
```

Compiler: gcc 13.3.0; ASan from the system toolchain; clang 18.1.3 also
available. XXHash absent, so the internal one-at-a-time hash is used; LYB
non-shrink mode does not check the context hash. The hardened pin loads its
internal YANG modules from files, so its driver run sets
`LY_TEST_SEARCHDIR=<hardened-src>/modules`; the vulnerable pin embeds them.

## Driver and evidence

`lyb_driver.c` is the only new source. `gen` uses `lyd_print_fd` because LYB is
binary and `strlen` truncates it at its first interior NUL (a failed first
experiment, preserved here). `valid.lyb` is 29 bytes,
sha256 `9c005b6982641a752998432eb51a58d53958fce835a11455cfd9fcb470074ad4`.

`bash run.sh` rebuilds as needed, compiles both drivers, regenerates the blob,
and writes six cases under `evidence/`. Normalization is deliberately absent:
raw ASan frames and RC lines are kept. Expected summary: vulnerable `none`
RC=0, `patch` and `patchmod` ASan heap-buffer-overflow (exit 1); hardened
`none` RC=0, `patch` RC=3, `patchmod` logs `LYB string length overflow.` and
RC=3, no ASan.

No socket, no listener, no external target is contacted at run time.
