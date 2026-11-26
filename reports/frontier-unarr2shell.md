# Frontier brief — unarr2shell (CVE-2026-111273 / GHSA-fj4h-mpx9-46qj)

Status: **staged 2026-11-26 by `frontier`, window 169, not admitted.**
Rungs 1–3 observed locally with the real public API and GCC+Clang ASan; rung 4
PARTIAL (fixed NUL byte at a code-determined offset), no r5. No vendor fix
exists in the public upstream tree despite the advisory's "patched 1.2.0"
claim — see the negative result below. Duplicate check before provisioning:
no prior `reports/frontier-*unarr*`, no unarr window, charter or mind on the
tape; `unarr` is absent from the plant's do-not-duplicate list. Admission is
the operator's; wake units and full-flag sync stay with the person.

## 1. Verified ground truth

- Claim: `https://github.com/selmf/unarr/security/advisories/GHSA-fj4h-mpx9-46qj`,
  published 2026-10-31T18:14:03Z, Moderate. Advisory title: "Heap buffer
  overflow (1-byte NUL write) in `tar_get_name()` when building USTAR
  prefix/name path". CVE via the advisory API: **CVE-2026-111273**;
  affected `<= 1.1.0`, advisory says patched `1.2.0`, API
  `first_patched_version: null`, no reference URLs.
- Claimed primitive: a spec-legal USTAR header with a full 100-byte `name`
  field and a full 156-byte `prefix` field makes `strcat(prefixed, name)`
  write a NUL one byte past a 257-byte heap allocation. Advisory reports
  ASan `WRITE of size 101` at `tar/parse-tar.c:253`, 0 bytes after a
  257-byte region from `parse-tar.c:243`, reached through the real public
  API `ar_open_tar_archive` → `ar_parse_entry` → `ar_entry_get_name`.
  No RCE claim; advisory explicitly says no exploit chain past the OOB write.
- Source pins: v1.1.0 source tarball SHA-256
  `4dc03f03e6215c4fcba4927962c7551c1eea690ae6de7c6251de4006d76adfd5`;
  raw `tar/parse-tar.c` at v1.1.0
  `d07acabdfb4c8d1b1673f81daafb3fd0cc6c563a053797e6e6127ad2f797ce14`;
  at v1.2.0 and v1.2.1 both
  `bd9bf8d99e1274ba6a870c39ee694c80843dc3b7821fca7b219bef480f3a4482`.
  Full URL/hash ledger in `lab/frontier/unarr2shell/PROVENANCE.md`.

## 2. Source-bound mechanism read from the patch

No fix hunk exists to read (see §4). The vulnerable code is verbatim at
`tar/parse-tar.c:240-253` of all four tags:

```
name = malloc(100 + 1);                 /* 101 bytes */
...
name[100] = '\0';                       /* name capped at 100 chars */
if (tar->entry.is_ustar) {
    char *prefixed = malloc(256 + 1);   /* 257 bytes */
    ...
    if (prefixed[0] != '\0') {
        prefixed[156] = '\0';           /* prefix capped at 156 chars */
        strcat(prefixed, "/");          /* writes at 156..157 */
        strcat(prefixed, name);         /* 100 chars at 157..256 + NUL at 257 */
```

Required worst case = 156 + 1 + 100 + 1 = 258 bytes; allocated 257. Both
capped lengths are set by the code, so the overflow is deterministic and not
dependent on attacker-controlled variable lengths — only on the two fields
being full and non-NUL-terminated. The advisory's suggested fixes (allocate
258, cap prefix to 155, or use `snprintf`) were not applied upstream.

## 3. Local evidence and rung-4 feasibility

Harness `lab/frontier/unarr2shell/` builds the v1.1.0 library with ASan
(`-O0 -g -fno-omit-frame-pointer`) and drives it only through public APIs.
`harness/make-poc.py` constructs the crafted USTAR header with a correct
checksum, plus two safe controls.

`bash harness/run-all.sh`: **7 PASS / 0 FAIL, rc 0**. GCC ASan attack run:
`AddressSanitizer: heap-buffer-overflow`, `WRITE of size 101`, 0 bytes after
a 257-byte region, frame `tar_get_name pinned parse-tar.c:253`, allocation
`parse-tar.c:243`, caller `ar_entry_get_name common/unarr.c:65`, driver
`harness/driver.c:35`. Shadow byte at the fault is `01` (one byte). Clang ASan
reproduces the same report at `parse-tar.c:253:17`. Safe controls (name 99 or
prefix 155) and the synthetic +1-byte fixed control are clean.

Rung 3 is **verbatim** (upstream bytes, real public API, real allocator).
Rung 4 is **PARTIAL**: the offset is code-determined and the written byte is
always `\0`; no chosen bytes, no pointer control, no adjacent live object,
no benign command marker, no wire request and no r5. A one-byte NUL heap
corruption is a plausible glibc metadata primitive in principle, but nothing
in this lab exercises it; the consumer after the write is `printf("%s")` in
the harness, not a `free` or allocator action.

## 4. Negative result: the advisory's fixed version is not fixed

Raw `parse-tar.c` at v1.1.0, v1.2.0 and v1.2.1 all contain the identical sink
at the identical lines (v1.2.0/1 hashes equal). The only diff between v1.1.0
and v1.2.0 in that file is an unrelated PAX `max_size` fix. GitHub's commit
list shows no commit touching `tar_get_name` since 2020 and no security-fix
branch. Therefore **no fixed control from the vendor is available**; the lab
control is a locally applied one-line `malloc(256 + 2)` change, explicitly
synthetic. Any claim that 1.2.0 or 1.2.1 fixes this bug is UNKNOWN-to-false
until a real patch appears. This is preserved as a negative result, not
retried into existence.

## 5. Cheapest next experiment

For a dedicated mind: (1) push rung 4 by placing a live allocation adjacent
to `prefixed` under a real (non-ASan) allocator and observing whether the NUL
lands in an adjacent object's length/refcount field before `printf`; that is
the only available byte-control path. (2) Track upstream for a real fix
commit and replace the synthetic control with it. (3) Check whether any
real caller (e.g. SumatraPDF's archive listing) takes the USTAR-prefix path
with attacker-supplied archives over a network boundary — none was observed
here, and no external probing is authorized.

## 6. Ceiling / UNKNOWNs

No RCE, no pointer overwrite, no r5. Fixed-version information is
contradicted by raw bytes. Real-world reachability beyond "any app that
lists entries of an attacker-supplied tar" is UNKNOWN. Witness replay is
owed; the author's run is not independent acceptance.
