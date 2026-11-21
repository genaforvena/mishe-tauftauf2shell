# Provenance — netatalk2shell frontier harness

All bytes below were fetched read-only from public upstream sources on
2026-11-21 ~04:53Z. Nothing outside the lab was probed.

## Claim sources

- Maintainer security advisory GHSA-5443-v9xg-mqgv,
  <https://github.com/Netatalk/netatalk/security/advisories/GHSA-5443-v9xg-mqgv>
  (published 2026-05-28, High 7.5, `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`,
  CVE-2026-45698).
- CVE record <https://www.cve.org/CVERecord?id=CVE-2026-45698> (published
  2026-08-17): affected `>= 3.1.19, < 4.4.3`, fixed 4.4.3.
- Netatalk's own advisory <https://netatalk.io/security/CVE-2026-45698>
  states affected 3.2.0–4.4.2 and disclosure 2026/05/13. The GHSA metadata
  version field (`3.1.19 < 4.4.2`) disagrees with its own patched version and
  with the CVE on whether 4.4.2 is affected; the pinned 4.4.2 source below
  settles that question locally: it contains the vulnerable expression.
- Release notes <https://netatalk.io/4.4/ReleaseNotes4.4.3>.

## Upstream fix

Commit `33dbda708cd38ee4ffa568cc5dde1fda4f900dfe`,
"CVE-2026-45698,CVE-2026-45699: afpd: fix stack buffer overflow in copydir()
and deletedir()", parent `8b3e33daaee0c65304c01ceda78db7cce0d8f28c`,
<https://github.com/Netatalk/netatalk/commit/33dbda708cd38ee4ffa568cc5dde1fda4f900dfe.patch>.
It makes exactly three one-line `strlen(...)`→`sizeof(...)` changes in
`etc/afpd/directory.c` (deletedir line 168; copydir lines 259 and 262).
The copydir half is CVE-2026-45699 and is out of this brief's scope.

## Pinned source bytes

Fetched with `curl -fsSL` from `raw.githubusercontent.com/Netatalk/netatalk/<ref>/etc/afpd/directory.c`:

| ref | meaning | sha256 | bytes |
| --- | --- | --- | --- |
| `d2ef3e298772aa96eaf83d3db147a5df919093ff` | annotated release tag `netatalk-4-4-2` dereferenced to commit | `82d5f3fddfe44331bd575a7559f3357eb3f40a4179aca674c8e6fe395dfc16eb` | 94593 |
| `79b13d9e7c77d3ab0e8b36c639fd3eb05ec06f04` | annotated release tag `netatalk-4-4-3` dereferenced to commit | `bd23b576228e1e88d85ef4e970d1ff8462d9004655664ee5d54795db0ea43152` | 94593 |

The two release files differ **only** in the three fix lines
(`diff -u` verification at pin time); the substitutions keep the same byte
length, which is why both files are 94593 bytes. Line 168 of the affected pin
is `    remain = strlen(path) - len - 1;`, line 168 of the fixed pin is
`    remain = sizeof(path) - len - 1;`. The vulnerable `strcpy` is at line
181, `char path[MAXPATHLEN + 1];` at line 149 and the function begins at line
147. `run.sh` asserts all of these and verifies both sha256 values before it
compiles anything.

## Harness boundary

`driver.c` concatenates verbatim pinned source lines 147–203 of each release
under `#line 147 "directory.c"` into `gen_block.h`. Collaborators (`opendirat`,
`readdir`, `ostatat`, `closedir`, `netatalk_unlinkat`, `netatalk_rmdir`,
`vol_syml_opt`) are harness stubs; the synthetic `DIR` is never passed to
libc. `MAXPATHLEN` is set to 1024 in the lab, matching the advisory's
"`char path[MAXPATHLEN + 1]` is 1025 bytes" description. The frame-offset
probe uses `__builtin_frame_address(1)` from a stub; it is instrumented
scaffolding, not a claim about a shipping compiler's frame layout. A
`setjmp`/`longjmp` escape observes the buffer before the overflowed return
address is used; no execution of attacker bytes occurs. No daemon, socket,
mount or AFP session is created.
