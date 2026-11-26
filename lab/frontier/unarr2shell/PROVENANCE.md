# PROVENANCE — unarr2shell W244 (2026-11-26)

All fetches were read-only provisioning from public GitHub sources. No external
target was probed; every run below is local.

## Claim and fetched URLs

- Advisory: <https://github.com/selmf/unarr/security/advisories/GHSA-fj4h-mpx9-46qj>,
  title "Heap buffer overflow (1-byte NUL write) in `tar_get_name()` when
  building USTAR prefix/name path", published 2026-10-31T18:14:03Z, Moderate.
- CVE via `https://api.github.com/repos/selmf/unarr/security-advisories/GHSA-fj4h-mpx9-46qj`:
  **CVE-2026-111273**. Vulnerable range `<= 1.1.0`, advisory `Patched versions:
  1.2.0`, `first_patched_version: null`, no reference URLs in the API record.
- Source tarball: `https://codeload.github.com/selmf/unarr/tar.gz/refs/tags/v1.1.0`
  → `src-v1.1.0.tar.gz`, SHA-256
  `4dc03f03e6215c4fcba4927962c7551c1eea690ae6de7c6251de4006d76adfd5`.
  Extracted to `unarr-1.1.0/` (gitignored build input).
- Tag list via `https://api.github.com/repos/selmf/unarr/tags?per_page=20`:
  `v1.2.1 704ea083dd38`, `v1.2.0 f1412d847491`, `v1.1.1 b211040df83d`,
  `v1.1.0 ca745b72684e`.
- Raw `tar/parse-tar.c` pins via `https://raw.githubusercontent.com/selmf/unarr/<tag>/tar/parse-tar.c`:
  - `pinned/parse-tar-v1.1.0.c` SHA-256
    `d07acabdfb4c8d1b1673f81daafb3fd0cc6c563a053797e6e6127ad2f797ce14`.
  - `pinned/parse-tar-v1.2.0.c` and `pinned/parse-tar-v1.2.1.c` both SHA-256
    `bd9bf8d99e1274ba6a870c39ee694c80843dc3b7821fca7b219bef480f3a4482`.

## Patched-version discrepancy (negative result)

The advisory claims 1.2.0 is patched. Raw bytes at v1.1.0, v1.2.0 and v1.2.1
all contain the same sink at the same lines:

```
243:            char *prefixed = malloc(256 + 1);
251:                prefixed[156] = '\0';
252:                strcat(prefixed, "/");
253:                strcat(prefixed, name);
```

`diff -u pinned/parse-tar-v1.1.0.c pinned/parse-tar-v1.2.0.c` shows a single
unrelated change in `tar_handle_pax_extended` (`max_size` calculation); nothing
in `tar_get_name`. The commit list fetched from
`https://api.github.com/repos/selmf/unarr/commits?per_page=15` shows no commit
touching this function after 2020 (`31ab60c88305`), and the branch list has no
security-fix branch. **No vendor fix exists in the public upstream tree for
this advisory.** The fixed control in this lab is a *synthetic* one-line change
`malloc(256 + 1)` → `malloc(256 + 2)` in a copy of v1.1.0
(`src-locally-fixed/`), not a vendor release. Treat any "fixed version" claim
as UNKNOWN until a real fix commit appears.

## Mechanism (source-bound, verbatim)

`tar_get_name()` in `tar/parse-tar.c` allocates `prefixed = malloc(256 + 1)`
(257 bytes), reads 167 bytes from the USTAR header at offset 345, then for a
nonempty prefix sets `prefixed[156] = '\0'`, appends `"/"` and appends `name`,
where `name = malloc(100 + 1)` and `name[100] = '\0'`. Worst case is
156 + 1 + 100 + 1 = 258 bytes: the final NUL from `strcat(prefixed, name)`
lands one byte past the 257-byte allocation. The written value is always NUL;
the byte at offset 257 is not attacker-chosen. Both source strings are capped
by the code itself, so the overflow is deterministic when both header fields
are full-length and non-NUL-terminated.

## Harness files and hashes

- `harness/driver.c` SHA-256
  `16258974dae175312a4df9cad329c2adc5a5b9410b659d097319c652ea13c88f` —
  real public API only: `ar_open_file` → `ar_open_tar_archive` →
  `ar_parse_entry` → `ar_entry_get_name`. No internal/synthetic call.
- `harness/make-poc.py` SHA-256
  `6f7bdcada7872cfb6ae7d8d13734dbc58fea82bee0a37eb624d2da15ddf0a22f` —
  builds `attack.tar` (name 100 / prefix 156) plus two safe controls from
  the advisory's Python recipe, with correct USTAR magic and checksum.
- `harness/run-all.sh` SHA-256
  `fc8a0be05461ad8fcb571f857a37cee7e6586a49c2a8293c7e8dbae6544d3b12` —
  CMake `-DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF -DENABLE_7Z=OFF`,
  `-fsanitize=address -fno-omit-frame-pointer -g -O0`; GCC vulnerable/fixed
  plus Clang vulnerable (project adds `-flto`, so the driver links with
  `-flto` too).
- `run-witness.sh` rehashes all seven inputs, deletes `build/`,
  `src-locally-fixed/` and `evidence/`, and reruns everything.

## Observed output (W244, 2026-11-26)

`bash lab/frontier/unarr2shell/harness/run-all.sh` from the checkout root:
`TOTAL: 7 PASS / 0 FAIL`, exit 0.

`evidence/asan-vuln-attack.out` (GCC ASan, attack.tar):

```
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 101 at 0x512000000141 thread T0
    #0 strcat  asan_interceptors.cpp:515
    #1 tar_get_name  unarr-1.1.0/tar/parse-tar.c:253
    #2 ar_entry_get_name  unarr-1.1.0/common/unarr.c:65
    #3 main  harness/driver.c:35
0x512000000141 is located 0 bytes after 257-byte region
allocated by thread T0 here:
    #1 tar_get_name  unarr-1.1.0/tar/parse-tar.c:243
```

Shadow byte at the touched address is `01` (one partially addressable byte),
matching the advisory's exactly-one-byte overflow.

`evidence/asan-clang-vuln-attack.out` (Clang ASan): same `WRITE of size 101`,
frame `tar_get_name ... parse-tar.c:253:17`, 0 bytes after the 257-byte region.

`evidence/asan-vuln-safe-short-name.out` and
`evidence/asan-vuln-safe-short-prefix.out`: clean, rc 0 — both header fields
must be full length. `evidence/asan-fixed-attack.out`: clean, rc 0 — the
synthetic +1-byte allocation removes the fault (this is a control, not a
vendor fix).

## Ceiling

Rung 3 observed with a verbatim upstream sink and the real documented API.
Rung 4 is PARTIAL at best: the overflow location is determined by the code,
and the only byte past the allocation is a fixed NUL — no chosen bytes, no
pointer control, no live command side effect, no wire input, no r5.
