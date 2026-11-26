# PROVENANCE — quickjsbcode2shell lab (W271, 2026-11-26)

## Pins and claim sources

- CVE-2026-88378 / GHSA-jww9-7qmq-6hv5:
  https://github.com/advisories/ghsa-jww9-7qmq-6hv5 (unreviewed, published
  2026-09-24; Critical 9.8 AV:N).
- Fix commit `42526037cfc0b2a94a875c0de0f4bbeaf597a542`; GitHub commit API
  confirms parent `04be246001599f5995fa2f2d8c91a0f198d3f34c`, used as the
  vulnerable pin. Upstream has no release tags; no numeric versions claimed.
- Patch `.patch` fetched from the fix commit; it modifies `quickjs.c`,
  `tests/bjson.c` and `tests/test_bjson.js`. The 21-byte attack input is the
  upstream regression array in `tests/test_bjson.js`.
- No published Python/CVE record was used as a source of truth; advisory prose
  is a claim reproduced only in this local harness.

## Exact delivered bytes

| artifact | sha256 |
| --- | --- |
| `src/quickjs-vuln.tar.gz` (commit 04be2460…) | `2a87ffcca6c870f764ce70a7736351bd7cff3dc1fb95a8fb059c260979f1e01a` |
| `src/quickjs-fixed.tar.gz` (commit 42526037…) | `bd32b79944dc7a46fcebaf144eedbe4d76eeca4ec102043863ee46d224d561b2` |
| verbatim `quickjs.c` at 04be2460… | `a68622cecb806f39bf24738c376a0a73032ea8913478cad702e0265c46f7999f` |
| verbatim `quickjs.c` at 42526037… | `c228e1c185faca75bb5764c211d35b0d3901cdafe7293491917fdb9350fe68b8` |
| `run-all.sh` (staged) | `7031c42086ccaad2ee329b18c597cd0fc2b62fe98dd9a6c30f249bc3c09b1cd5` |
| `harness/driver.c` (staged) | `d0b4d88b51a52dbb2c2677b137472b9c3bc96bfd372236378404a432ecfde26e` |
| `evidence-run-console.log` (staged) | `0744a26e09b5d7044da1a128ecabd1f7428bd93bbf1110058cbfd70e24a3a02f` |

Tarballs and extracted `build/` trees are gitignored; refetch with:

```
curl -fsSL -o src/quickjs-vuln.tar.gz \
  https://github.com/bellard/quickjs/archive/04be246001599f5995fa2f2d8c91a0f198d3f34c.tar.gz
curl -fsSL -o src/quickjs-fixed.tar.gz \
  https://github.com/bellard/quickjs/archive/42526037cfc0b2a94a875c0de0f4bbeaf597a542.tar.gz
./run-all.sh > evidence-run-console.log 2>&1
```

## Build and observation

- `harness/driver.c` is lab-only and calls the public `JS_ReadObject()`,
  `JS_WriteObject()`, `JS_EvalFunction()` and runtime/context APIs. It
  compiles against the verbatim upstream `quickjs.c`, `dtoa.c`,
  `libregexp.c`, `libunicode.c` and `cutils.c` from each commit. No upstream
  source line is edited.
- Build-only flags: `-std=gnu99 -O0 -g -fno-omit-frame-pointer
  -fsanitize=address -D_GNU_SOURCE -DCONFIG_VERSION="<upstream VERSION>"
  -include limits.h -lm -ldl -lpthread`. `CONFIG_VERSION` and `_GNU_SOURCE`
  mirror upstream `Makefile`; `-include limits.h` supplies `INT_MAX` used by
  the fixed patch without altering source bytes.
- Measured `RESULT PASS=25 FAIL=0 rc 0` at 13:57Z.
- Attack: exact 21-byte upstream regression buffer, `JS_READ_OBJ_BYTECODE`.
  GCC ASan `heap-buffer-overflow`, `WRITE of size 96`, `0 bytes after 88-byte
  region`, frame `JS_ReadFunctionTag build/vuln/quickjs.c:38820`.
- Fixed: rc 0, `SyntaxError: integer overflow while reading bytecode`, no
  ASan report. Safe bytecode round-trip: `read_exception=0`, `value=2` in both
  builds, no ASan report.

## Preserved negatives and corrections

- Clang 18 with the same ASan flags reported nothing on the attack input
  (`exception=0`, rc 0). This is an observed compiler-dependent detection
  gap, recorded as an explicit runner check, not treated as a fixed control.
- First safe-bytecode driver draft double-freed the function object because
  `JS_EvalFunction()` consumes it; ASan reported a UAF at `driver.c:72`.
  Driver now sets `obj = JS_UNDEFINED` after evaluation and flushes stdout.
  That was a harness bug, not part of the target finding.
- QuickJS-NG GHSA-r6vf-p8wr-4vg9 (wall backup) is a different repository;
  its advisory URL returned 404 when fetched. Not reused here.
- No wire consumer, chosen-offset read-back, pointer steering, command or r5
  was observed. No external host was contacted beyond public source fetches.
