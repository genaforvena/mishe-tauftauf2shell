# PROVENANCE — gpgme2shell lab (CVE-2026-129975)

## Pinned inputs (read-only provisioning, no external probing)

- `pinned/engine-gpg.c`: raw
  `https://raw.githubusercontent.com/gpg/gpgme/gpgme-2.2.0/src/engine-gpg.c`,
  sha256 `c4ef11bda841fc6d07c83063c6968a6db50db3393af2d661054c59b979311d55`
  (4325 lines). Vulnerable statements: `read_status()` :1481-1612,
  `read_colon_line()` :1633-1732, `gpg_release()` free :601-602.
- `pinned/fix.patch`: upstream commit diff
  `https://github.com/gpg/gpgme/commit/14499348b966cd7b3d72afee15a5cd51cdd0a727.patch`,
  sha256 `2fde658ab8b32439c14f58c214f2463b4109aa68d9cbd26c432f17303049c500`.
- Advisory facts from NVD/GHSA, vendor and oss-security; see the brief.

## Build and replay

From this directory, `sh run.sh` (POSIX sh, `cc`, `sha256sum`): checks both
pins and three source-shape assertions, then compiles four variants:

```
cc -std=c99 -g -O0 -fsanitize=address -fno-omit-frame-pointer -o vuln-asan harness.c
cc -std=c99 -g -O0 -fsanitize=address -fno-omit-frame-pointer -DFIXED -o fixed-asan harness.c
cc -std=c99 -g -O0 -o vuln-plain harness.c
cc -std=c99 -g -O0 -DFIXED -o fixed-plain harness.c
```
Clean `git archive HEAD lab/frontier/gpgme2shell | tar x -C /tmp/w210-gpgme`
replay of commit `88addf93` also gave 19 PASS / 0 FAIL.

Each binary is run as `./<bin> <attack|safe> <byte> <offset>`; stdout/stderr
and rc land in `evidence/<case>.out` and `.rc`. Final in-tree run: 19 PASS /
0 FAIL, rc 0. Attack bytes 0x48 and 0x5a at relative offset 1000 (buffer
offset 1014) are chosen by the runner, not hardcoded in the vulnerable path.

## Known limits / negatives

- Extracted static functions with stand-in `status.fnc`, I/O read and struct;
  no full GPGME build, no gpg process, no pipe or socket, no live consumer.
- ASan flags the second free in `release()`; the first free is the pinned
  `realloc()` in `read_status()` and the stale pointer is printed as
  `published=old`. Intra-object state is not otherwise observed.
- Plain glibc behavior changed between harness revisions (an earlier revision
  aborted with `free(): double free detected in tcache 2`; the final one exits
  0). This is preserved as a contradictory observation and left UNKNOWN.
- The advisory is AV:N but the lab exercises a prefilled header line, not a
  network or pipe input; wire reach stays UNKNOWN.
- No pointer/IP/command control, no allocator metadata claim, no rung 5.
  Dedicated window and registry entry are live; operator admission PENDING.
