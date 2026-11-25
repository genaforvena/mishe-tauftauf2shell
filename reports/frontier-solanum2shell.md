# frontier brief — solanum2shell (CVE-2026-121603)

Status 2026-11-25 12:40Z: STAGED locally; brief and pinned ASan harness
written. No admission or window is claimed by this brief; the operator owns
admission. Window 156 was created by frontier before handoff.

## Verified ground truth

- Claim: CVE-2026-121603 / GHSA-6cq2-4j8w-7hvj, published 2026-11-03,
  https://osv.dev/vulnerability/CVE-2026-121603 and
  https://github.com/advisories/GHSA-6cq2-4j8w-7hvj . OSV/CVE text:
  "Solanum before commit 2ea1382 Buffer Overflow via Server-to-Server KILL
  Handler". CVSS:4.0 `AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N` (8.5 HIGH
  per GHSA/NVD summary); GHSA API also carries CVSS:3.1 6.5
  `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N`. CWE-120.
- Prerequisite: a malicious **authenticated linked server** (PR:H) sends an
  overlong KILL reason. The upstream fix commit text notes that a linked
  server can already introduce a remote operator authorized for DIE, so
  availability impact is not counted in practice.
- Vulnerable pin: parent `7bc7e34c04711247b932666e19ae900cba884540`,
  `modules/core/m_kill.c` (sha256 `f4af269d…`, full value in
  `lab/frontier/solanum2shell/pins/SHA256SUMS`). Upstream fix
  `2ea1382e4262b212a91034258c466f0f6754cd61` (PR #550, authored
  2026-08-15, one file, +4/-0), fixed pin sha256 `b1408e51…`. Both full
  files are in `lab/frontier/solanum2shell/pins/`.
- Not a duplicate: Solanum appears in `reports/frontier-bacnet2shell.md:123`,
  `reports/frontier-pgpool2shell.md:158` and
  `reports/frontier-ud3tn2shell.md:186` only as a **screened, unworked**
  candidate ("not chosen", "noted for a later wake"). No Solanum charter,
  window, brief or lab tree existed before this wake. `tacplus2shell`
  (pppd) and `tac_plus-ng` are different projects; not used here.

## Source-bound mechanism (pinned bytes)

- `ms_kill()` at vulnerable pin `:170-280` splits `parv[2]` via
  `LOCAL_COPY()` + `strchr(s, ' ')`, taking everything after the first
  space as `reason` (`:184-196`). There is no length check on that reason.
- The store is `sprintf(buf, "Killed (%s %s)", source_p->name, reason)` at
  vulnerable pin `:277`. `buf` is `static char buf[BUFSIZE]` at `:44`;
  upstream `include/ircd_defs.h:78` pins `BUFSIZE 512`, and the *client*
  handler `mo_kill()` already truncates to `KILLLEN 200`
  (`include/ircd_defs.h:71`) at `m_kill.c:91-92`. The server handler lacked
  that truncation.
- The fix adds exactly four lines at fixed pin `:200-203`:
  `if(strlen(t) > (size_t) KILLLEN) t[KILLLEN] = '\0';` before `reason = t`.
  No other hunk in the commit. Fixed store at `:281` is byte-identical to
  the vulnerable store at `:277`.
- `LOCAL_COPY` is `strdupa()` at upstream `include/stdinc.h:52`; the harness
  uses an exact-length heap copy so no overflow occurs before the pinned
  `sprintf`.

## Cheapest local experiment and observed result

`lab/frontier/solanum2shell/harness/` includes both `ms_kill()` bodies
**verbatim** (vulnerable `:170-280`, fixed `:170-284`, sha256 recorded at
build time) with stand-in `Client` structs, constants and no-op peers.
`bash harness/run-all.sh` → **18 PASS / 0 FAIL** (GCC and Clang):

- Pin sha256 2/2, both extracted bodies byte-identical to the pinned ranges,
  fixed/vuln identical through `:197`.
- GCC and Clang ASan vulnerable builds, reason 510 and 700 bytes:
  `global-buffer-overflow`, `WRITE of size 533` (reason 510) in the pinned
  `sprintf` at harness `pinned_vuln.h:108` = upstream `m_kill.c:277`,
  `0 bytes after global variable 'buf' … of size 512`.
- Reason 480 bytes is clean on both compilers (`buf_len=502`), so the fault
  is length-gated, not an artifact of the harness.
- Fixed pin with 510/700-byte reason: clean; the four-line truncation keeps
  the same crafted reason below `BUFSIZE`.
- Plain GCC vulnerable build with reason 510: `buf_len=532` and
  `oob=-SOLANUM-OOB-MISHE-)` past `buf+512`; the bytes are chosen by the
  crafted reason, at a deterministic offset derived from prefix length.

## Feasibility assessment and ceilings

- Rung 1 (trigger): deterministic crafted `parv[2]` through the real pinned
  handler; no external probes.
- Rung 2 (state failure): reason length accepted without the `KILLLEN`
  truncation that the client-side handler applies.
- Rung 3: GCC and Clang ASan global-buffer-overflow WRITE in the verbatim
  pinned `sprintf`.
- Rung 4: PARTIAL — the overflow length and stored bytes are chosen by the
  crafted input at a known offset past a 512-byte global. The allocation is
  a stand-in `buf` in the harness, not the real ircd process image; no
  adjacent function pointer, allocator grooming, pointer-IP or chosen
  control-flow target measured. The upstream report's RCE wording is a
  claim, not an observed result here.
- Rung 5: NOT CLAIMED — no real ircd build, no linked-server wire path, no
  command side effect, no vulnerable/fixed live-process control.
- Caveat: PR:H (authenticated server link) bounds impact; the vulnerability
  is an S2S handler, not a client-facing one. OSV/CVSS4 and GHSA/CVSS3.1
  scores differ; both are quoted rather than reconciled.

## Cheapest next experiment for a target mind

Build Solanum at `7bc7e34` and at `2ea1382` under ASan, connect a lab-only
server link on 127.0.0.1, and send a real S2S `KILL` whose reason exceeds
`BUFSIZE - prefix` with a distinct marker at each trailing offset. Observe
the real global layout after `buf`: if a pointer is adjacent, test whether
chosen bytes reach a dereference with vulnerable/fixed/safe controls. Until
that is measured, this stays a pinned-function claim and rung 4 PARTIAL.

All local work stayed in `lab/frontier/solanum2shell/`; advisory/commit fetches
were read-only provisioning and no external system was contacted with a probe.
