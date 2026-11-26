# PROVENANCE — libxml22shell (frontier W236, 2026-11-26)

## Provisioning (read-only fetches, no external probing)

    curl -fsSL -o pins/dict-v2.15.3.c https://raw.githubusercontent.com/GNOME/libxml2/v2.15.3/dict.c
    curl -fsSL -o pins/dict-v2.15.4.c https://raw.githubusercontent.com/GNOME/libxml2/v2.15.4/dict.c
    curl -fsSL -o /tmp/dict-master.c https://raw.githubusercontent.com/GNOME/libxml2/master/dict.c
    curl -fsSL https://github.com/GNOME/libxml2/commit/a4cba4b5b5a8c42e155ed42d2d2a44955465a2e4.patch

Fix patch subject: "fix: add overflow checks to xmlDictAddQString in dict.c",
2026-04-16, 15 insertions / 4 deletions in `dict.c`.
Master `dict.c` SHA-256 equals v2.15.4 `dict.c` SHA-256 (byte-identical).

## Pins (SHA-256)

| artifact | sha256 |
| --- | --- |
| `pins/dict-v2.15.3.c` | `416253664eb3d95a393be6c61c649a1b5600729bbd1e3ce9123df08b12d8f388` |
| `pins/dict-v2.15.4.c` | `2663392f29dd45eb7ad802c471e146d4f6f509e317a4938b496920b4ea0228b4` |
| `pins/dict-vulnerable.inc` | `c2a4a0ed9ffe8fabffc9f0e19de8c3d1ca59fee80dc68f454211ad511a7f0d9a` |
| `pins/dict-fixed.inc` | `035611cca31f6bdb67b030c221c8fb7445750d841479e6f4f2a7e8874c28b9d4` |

Excerpt extraction (byte-exact, no reformatting):

    sed -n '196,245p' pins/dict-v2.15.3.c > pins/dict-vulnerable.inc
    sed -n '196,256p' pins/dict-v2.15.4.c > pins/dict-fixed.inc

The vulnerable excerpt is the whole `xmlDictAddQString()` definition; the
fixed excerpt is the same definition with the a4cba4b5 guard hunk.

## Harness facts

- `harness/driver.c` supplies stand-in `xmlChar`, `xmlDictStrings`,
  `xmlDict`/`xmlDictPtr`, a 1 GiB-capped `xmlMalloc`, and the caller. The two
  pinned bodies are `#include`d verbatim; no pinned bytes are edited.
- `sizeof(xmlDictStrings) == 48`; `offsetof(xmlDictStrings, array) == 40`;
  pool allocation `48 + 1000 == 1048` bytes; 8 bytes of tail padding sit
  between `array[1000]` and the allocation end. ASan therefore reports the
  first out-of-allocation byte at pool+1048.
- Source buffer is a sparse 2^32-byte `MAP_PRIVATE|MAP_ANONYMOUS` mapping,
  initially RW, then `mprotect`ed read-only. Only touched pages are resident.
- Case `attack`: `plen=15`, `namelen=0xfffffff0`, 32-bit `sum+1` wraps to 0.
- Case `wrap1k`: `plen=1000`, `namelen=0xffffffff`, 32-bit `sum+1` wraps to
  1000, true size_t sum 2^32+1000.
- Case `safe`: `plen=15`, `namelen=16`, no wrap.
- Plain mode returns an interior pool pointer from a single 1112-byte
  allocation, with a 64-byte `0x5a` canary at pool+1048, and catches SIGSEGV
  with `sigsetjmp`/`siglongjmp`. Chosen source index is
  `1048 - 40 - plen - 1 = 992 - plen` for `plen=15`.

## Verification

    cd lab/frontier/libxml22shell
    bash run-all.sh

Author run 2026-11-26 00:09Z: **26 PASS / 0 FAIL**, rc 0. Raw logs in
`out/gcc-attack.log`, `out/clang-attack.log`, `out/fixed-attack.log`,
`out/vuln-wrap1k.log`, `out/fixed-wrap1k.log`, `out/vuln-safe.log`,
`out/fixed-safe.log`, `out/plain-attack.log`, `out/plain-safe.log`.

Key observed lines:

    ==2924140==ERROR: AddressSanitizer: heap-buffer-overflow
    WRITE of size 4294967280
    #2 xmlDictAddQString pins/dict-vulnerable.inc:45
    0x... is located 0 bytes after 1048-byte region
    SIGSEGV_CAUGHT=1
    CANARY_AFTER=4d495348452d4c4942584d4c32212100

Negative preserved: `out/fixed-attack.log` shows the same ASan WRITE with the
pinned v2.15.4 body; the a4cba4b5 guard's outer condition still uses the
wrapping 32-bit expression, so the wrap-to-zero case is unfixed in v2.15.4 and
master. `out/fixed-wrap1k.log` shows `RET=NULL` and no ASan report, which is
the usable fixed control.

`run-witness.sh` rehashes all four pins and invokes `run-all.sh` from a clean
build directory; it is the one-command replay for the witness.

## Grade

Rung 3 pinned verbatim (GCC + Clang ASan WRITE), rung 4 PARTIAL (chosen bytes
past the pool in a plain-process canary). No real library build, no XML wire
input, no pointer, no command, no r5.
