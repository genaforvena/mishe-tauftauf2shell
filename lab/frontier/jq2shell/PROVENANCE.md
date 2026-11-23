# jq2shell harness provenance (2026-11-23 W146)

## Source and pins

Claim: GHSA-q3h9-m34w-h76f / CVE-2026-32316, published 2026-04-13, High 8.2,
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H, CWE-190 -> CWE-122. Advisory:
https://github.com/jqlang/jq/security/advisories/GHSA-q3h9-m34w-h76f ; CVE
record: https://www.cve.org/CVERecord?id=CVE-2026-32316 . Affected `<= 1.8.1`,
patched `1.8.2`. Upstream fix
`e47e56d226519635768e6aab2f38f0ab037c09e5` adds two integer-overflow guards
to `src/jv.c`; the advisory's PoCs need strings of about 2 GiB. Read-only fetch
from GitHub; no external probing.

`PINS.sha256` carries tarball, file, patch, tag and generated-slice hashes.
Tag `jq-1.8.1` = `4467af7068b1bcd7f882defff6e7ea674c5357f4`, tag `jq-1.8.2` =
`34f7186b86743a083a589741b6cea95293524108`. `src/jv.c.vuln` and
`src/jv.c.fixed` are byte-identical to those tags' `src/jv.c`. `jq-1.8.2`
NEWS.md lists the CVE and fix commit; the CVE record's product status is
commit-based (`< e47e56d`), a cosmetic difference from the advisory's
version-based range. No jq target appears in the plant's do-not-duplicate
list, brief set or window registry.

## Verbatim slices and stubs

`harness/run.sh` generates one driver per variant from four pinned slices:

- `jv.c.vuln:1113-1134` / `jv.c.fixed:1112-1138` — complete
  `jvp_string_copy_replace_bad()`; the fixed slice includes the 64-bit
  `maxlength` computation and `if (maxlength >= INT_MAX)` guard.
- `jv.c.vuln:1174-1198` / `jv.c.fixed:1178-1206` — complete
  `jvp_string_append()`; the fixed slice includes the `(uint64_t)currlen + len`
  guard at pinned `:1181-1184`. `#line` directives preserve pinned line
  numbers; ASan frames below are from those lines.

Everything else is harness scaffolding: pinned `jv`, `jvp_string` and
`jv_refcnt` field types from `jq-jq-1.8.1/src/jv.h` and `jv.c`, minimal
refcount/string helpers, a bounded `jvp_utf8_next()` (16 iterations), a
three-byte chosen-byte `jvp_utf8_encode()` macro, and allocator stubs. The
crafted geometry is `currlen = 0x7ffffffe`, `len = 2` (append) and
`length = 0x5555555b` (copy_replace_bad). `NDEBUG` models a release build:
the pinned `assert(out < s->data + maxlength)` at `jv.c.vuln:1127` would abort
a debug build before the write is observable.

The `memcpy` macro records the *requested* length from the verbatim expression
and caps the *executed* copy at 48 bytes at the pinned call site, so a 2 GiB
copy is observable without transferring 2 GiB. Plain builds allocate from
2 GiB of reserved `MAP_NORESERVE` virtual space so the pinned
`memcpy(news->data + currlen, data, len)` at `:1192` is addressable; ASan
builds allocate the exact 32-byte/6-byte string buffer so the first write is
classified. These are scaffolding choices, not source edits.

## Commands

```
cd lab/frontier/jq2shell/harness
./run.sh            # generate drivers + 8 gcc/clang plain/asan binaries
./check.sh          # 64 assertions on 12 runs, normalized trace hash
```

Rung 1/2: vulnerable append reports
`APPEND ALLOC=32 REQ1=2147483646 REQ2=2` — the pinned product wraps to 0 and
clamps to 32; both fixed guards report `APPEND REJECT=1` / `BAD REJECT=1`.
Vulnerable copy_replace_bad reports `BAD ALLOC=6` — `0x5555555b*3+1` wraps to
6 — with 16 chosen-byte writes.

Rung 3: gcc and clang ASan both report `heap-buffer-overflow`, `WRITE of size
48`, frame `jvp_string_append ... jv.c.vuln:1191`. An isolated `bad` argument
skips append and both compilers report `WRITE of size 3`, frame
`jvp_string_copy_replace_bad ... jv.c.vuln:1126`, in a 23-byte region (16-byte
header + 6-byte string + terminator). Fixed ASan runs are clean.

Rung 4: plain vulnerable builds write `5a` bytes 16 bytes past the 32-byte
allocation and past the 6-byte allocation (`APPEND SINK=5a...`,
`BAD SINK=5a...`, 16 bytes each). `evidence/gdb-chosen.out` shows
`news->alloc_length=32 currlen=2147483646 len=2` and `0x5a` bytes at
`news->data+32` and `+40` immediately after the pinned memcpy.

## Results and negative results preserved

- `PASS=64 FAIL=0` three consecutive working-tree runs; normalized trace
  `8d537806c87a39e1a41e5483a28a4a731e7d5fe970d6528f0dee207b13cef1e7` in all
  three (PIDs, addresses, paths, build ids excluded). Raw runs in `evidence/`.
  A clean `git archive HEAD lab/frontier/jq2shell reports/frontier-jq2shell.md`
  replay at commit `c040c1e` rebuilt and ran `PASS=64 FAIL=0` with the same
  normalized trace; replay evidence was not committed back to the tree.
- First draft set `alloc_length = 8`, so the unsigned subtraction in
  `jvp_string_remaining_space()` wrapped above `len` and the verbatim code
  took the fast path at `:1181`, producing a SEGV instead of the wrap path.
  Fixed to `0x7fffffff` (remaining space 1 < 2); the DBG line records it.
- First plain run had no 2 GiB reserved mapping, so the pinned second memcpy
  at `:1192` faulted after the first write. The reserved mapping makes the
  scoped plain observation possible; it is not a jq runtime behavior.
- A bad edit briefly dropped the pinned `hash` field from the stub struct and
  rebuilt nothing; the compiler error is in `evidence/build.log` history only
  in this note. The final `PINS.sha256` covers the final generated drivers.
- No jq build, configure/make, JSON input, jq process, file, socket, network,
  real allocator grooming, ASLR study, pointer control, ROP, command, marker
  side effect or witness verdict was attempted. Whether a realistic JSON/jq
  pipeline can build the ~2 GiB strings and reach these call sites, and what
  the overwritten heap bytes overlap in a real build, are UNKNOWN.
