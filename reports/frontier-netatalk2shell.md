# Netatalk2Shell — frontier brief

## Claim (verified ground truth from public sources, read only)

- **CVE-2026-45698 / GHSA-5443-v9xg-mqgv**, "Integer Underflow → Stack Buffer
  Overflow in `deletedir()`", published by the Netatalk maintainer 2026-05-28,
  CVE record published 2026-08-17.
  <https://github.com/Netatalk/netatalk/security/advisories/GHSA-5443-v9xg-mqgv>,
  <https://www.cve.org/CVERecord?id=CVE-2026-45698>.
- Severity is consistent across the two primary records: **High 7.5**,
  `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`. The maintainer advisory
  claims "potential remote code execution (authenticated) by overwriting stack
  return addresses; at minimum a reliably caused afpd worker crash (DoS)".
  That RCE claim is a claim, not an observation from this plant.
- Affected/fixed: CVE says `>=3.1.19, <4.4.3`, fixed 4.4.3. The project's own
  advisory says 3.2.0–4.4.2, and the GHSA metadata range (`3.1.19 < 4.4.2`)
  contradicts its own patched version. The pinned 4.4.2 source below contains
  the vulnerable expression, so 4.4.2 is affected regardless of metadata.
- Reachability gate from the advisory: `deletedir()` runs in `afpd` (the
  network-facing AFP file server) only when a file operation crosses a device
  boundary inside a shared volume, because `renameat()` cannot handle that.
  An authenticated AFP session (`PR:L`) and a mount point below the share root
  (`AC:H`) are required. The same fix commit also patches `copydir()`
  (CVE-2026-45699); that sibling bug is out of scope here.

## Mechanism, read from the patch — not from exploit narrative

Upstream fix commit
`33dbda708cd38ee4ffa568cc5dde1fda4f900dfe` (parent
`8b3e33daaee0c65304c01ceda78db7cce0d8f28c`) changes exactly three lines. In
`deletedir()` at `etc/afpd/directory.c:168`:

```diff
-    remain = strlen(path) - len - 1;
+    remain = sizeof(path) - len - 1;
```

`len` is `strlen(dir) + 1` after the `snprintf(path, MAXPATHLEN, "%s/", dir)`
and `len++`; `strlen(path)` is therefore equal to `len`, so the original
subtraction underflows `size_t` to `SIZE_MAX`. The guard at line 176,
`if (strlen(de->d_name) > remain)`, can never reject a real filename. Line 181,
`strcpy(path + len, de->d_name)`, then appends an attacker-chosen directory
entry name into `char path[MAXPATHLEN + 1]` (1025 bytes) with only two bytes
left. A `NAME_MAX` (255-byte) filename writes 256 bytes at offset 1023: 254
bytes past the stack object, crossing the saved frame pointer and return
address in a plain build. The fix makes `remain` the true capacity and the
existing check rejects the long name before the copy.

## Pins and local harness

Byte-exact source is pinned from the two release tags, not reconstructed:

| pin | commit | sha256 of `etc/afpd/directory.c` |
| --- | --- | --- |
| affected, release 4.4.2 | `d2ef3e298772aa96eaf83d3db147a5df919093ff` | `82d5f3fddfe44331bd575a7559f3357eb3f40a4179aca674c8e6fe395dfc16eb` |
| patched, release 4.4.3 | `79b13d9e7c77d3ab0e8b36c639fd3eb05ec06f04` | `bd23b576228e1e88d85ef4e970d1ff8462d9004655664ee5d54795db0ea43152` |

The two files differ only in the three fix lines; full URLs, tag dereferencing
and `diff -u` details are in `lab/frontier/netatalk2shell/PROVENANCE.md`.
`lab/frontier/netatalk2shell/run.sh` verifies both hashes and the exact
line numbers (147 function start, 149 buffer, 168 underflow/fix, 181 `strcpy`)
before compiling. `driver.c` includes verbatim pinned lines 147–203 under
`#line 147 "directory.c"`; collaborators are stubs feeding a synthetic
directory entry. No production statement is reimplemented, no daemon, socket,
mount or AFP session is created.

## Evidence ladder (observed 2026-11-21 ~04:59Z)

Working-tree replay of `bash lab/frontier/netatalk2shell/run.sh <outdir>`:
**24 PASS / 0 FAIL, `ALL CHECKS PASS rc 0`**, trace
`sha256=c1bba7fb17b2a2b0cf6de7c76725974f005192648287245f5ba3b8aac08339d0`
(canonical lines only; ASan PID/address/path text excluded). A clean
`git archive HEAD` replay at commit `bd30e2d`, run twice into separate
absolute output directories from the extracted tree, gave 24 PASS /
`ALL CHECKS PASS rc 0` both times with the same trace sha256 (byte-identical
between directories).

- **Rung 1 (reproducible trigger)** — pinned affected `deletedir()` with a
  1023-byte directory path and a 255-byte synthetic `d_name` performs
  `strcpy(path + 1024, d_name)`, writing 256 bytes (including NUL) into
  `char path[1025]`. `LAYOUT ... name_len=255 write_len=256 path_to_ret=1080
  ret_from_write=56 calls=1`. The upstream statements execute from verbatim
  pinned source lines 147–203 under `#line 147 "directory.c"`.
- **Rung 2 (observed state failure)** — the underflow makes
  `remain == SIZE_MAX`, so the `strlen(de->d_name) > remain` guard at pinned
  line 176 never fires. A pre/post snapshot of the caller's saved-return slot
  records `CAPTURE escaped=1 first_changed=0` — the first byte of that slot
  is overwritten by attacker-supplied filename bytes. The `longjmp` is
  harness scaffolding: the corrupted return address is never executed.
- **Rung 3 (ASan-confirmed corruption)** — `stack-buffer-overflow`,
  `WRITE of size 256`, frame `deletedir` at the real pinned
  `directory.c:181` (`strcpy`). ASan names the victim `path [240, 1265)`,
  exactly 1025 bytes, with the access at offset 1265.
- **Rung 4 (INSTRUMENTED)** — the 8-byte token `NET2SHEL`
  (`4e4554325348454c`) from the synthetic name is read back byte-exact at
  requested offsets 0 and 64 of the write (`chosen_offset` equals the
  request), and the same token is observed in the saved-return-address slot
  at offset 56 (`RET_SLOT ... attacker=... observed=... equal=1`). The
  patched 4.4.3 block with the same input never reaches `ostatat`: `calls=0`,
  `first_changed=18446744073709551615` (`SIZE_MAX`, i.e. no changed byte),
  `FIXED_NO_WRITE marker_never_reached=1`.
  **No live afpd process, no socket, no AFP session, no mount, no useful
  pointer control and no execution.** Return-address overwrite is observed
  only in the instrumented harness build, which escapes before using it.

## Rung-4 feasibility assessment

What helps: the write is an unbounded `strcpy` of attacker-controlled bytes
with no count clamp, so chosen bytes reach the saved return address in the
plain harness build; the advisory claims authenticated RCE and supplies an
unambiguous one-line A/B fix. Unlike the availability-only finds in this
plant, the primary CVSS records here include C:H/I:H.

What caps it: (1) `PR:L` plus an unusual cross-device layout inside the AFP
share (`AC:H`) — not a default deployment; (2) no real afpd binary, packet
path, authentication state or cross-device rename was exercised, so the
advisory's reachability claim stays a claim; (3) a shipping build with stack
protector/PIE/ASLR may stop or detect a naive return-address overwrite;
(4) `NAME_MAX` bounds the write to about 254 bytes past the buffer, which is
enough to cross the return address in this harness but leaves little room for
ROP under a different frame layout.

**Cheapest next rung:** build Netatalk 4.4.2 `afpd` under ASan, create a
loopback-only AFP share whose subtree contains a mount point from another
filesystem, authenticate, create a 255-byte filename there and trigger the
cross-device rename/delete that calls `deletedir()`. Capture the real ASan
frame and the `d_name` reaching pinned line 181; that promotes packet
reachability from claim to observed bytes and shows whether the shipping
build's hardening leaves the return address reachable.

## Handoff

Two required artifacts for a find: this brief and a live registered two-pane
`netatalk2shell` window. Window creation and registry entry are recorded at
yield time; the operator owns admission.
