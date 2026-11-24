# frontier-hydra2shell — CVE-2026-133274 (THC-Hydra Set-Cookie cookiejar)

**Verdict: rung 3 confirmed on a real loopback HTTP wire; rung 4 not
demonstrated. Recommend SCREEN OUT for a dedicated target mind/window.** The
primitive is a negative-length `strncpy` followed by a one-byte NUL write at
`tmpcookie[-1]`; the byte value and offset are fixed, the plain v9.7 build
does not crash, and the advisory's "crashes Hydra" claim did not reproduce in
this build. This is a genuine memory-safety bug with attacker-controlled wire
input, but it does not supply chosen bytes at chosen offsets or control flow.

## 1. Ground truth (claim sources, read-only provisioning)

- CVE-2026-133274, VulnCheck CNA, published/updated 2026-11-19. Title:
  "THC-Hydra through 9.7 Stack Buffer Overflow via hydra-http-form.c Cookie
  Handling". CWE-121. CVSS 4.0 7.1 HIGH
  (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`),
  CVSS 3.1 6.5 MEDIUM. Product status: `thc-hydra` affected from 0 through
  9.7. Credit: Umut SEVİNÇ (VulnSVNC).
  <https://www.cve.org/CVERecord?id=CVE-2026-133274>
- VulnCheck advisory (2026-11-19) repeats the claim: a malicious HTTP server
  sends a `Set-Cookie` header with an extra leading space followed by a
  repeated cookie name, causing a negative `strncpy` length that overflows
  `tmpcookie` and crashes Hydra.
  <https://www.vulncheck.com/advisories/thc-hydra-through-9.7-stack-buffer-overflow-via-hydra-http-form-c-cookie-handling>
- Patch referenced by the CVE:
  <https://github.com/vanhauser-thc/thc-hydra/commit/6ab9ad860ff92a18196566172a197070b3977f6e>
  (local commit `6ab9ad86`, "cookie fix", author/committer date 2026-11-07,
  one file `hydra-http-form.c`, +8/-3). Its parent is an ancestor of the
  `v9.7` release tag; the fixed tag number is **UNKNOWN** (patch landed after
  the 2026-05-03 `v9.7` tag on master).
- Pinned vulnerable tree: `v9.7` tag `6c11ce2dff19ce81630c12b001d821dcd4d1567c`
  (2026-05-03). Pinned fixed tree: patch commit `6ab9ad860ff92a18196566172a197070b3977f6e`.
  Both pulled by provisioning into `lab/frontier/hydra2shell/src/hydra-git`;
  no external system was probed.

All advisory prose above is a **claim**. The observations below are this
lab's measurements.

## 2. Source-bound mechanism (pinned v9.7 bytes, not rendered line claims alone)

`analyze_server_response()` loops over lines returned by
`hydra_receive_line()` and, for each `Set-Cookie:` header, copies the value
into a 1024-byte stack `str`, derives a 128-byte stack `tmpname` up to the
first `=`, and searches the global 4096-byte cookie jar `cookie` for that
name (`hydra-http-form.c:769-829` in v9.7):

```c
if ((ptr = hydra_strcasestr(cookie, tmpname)) != NULL) {
  if (ptr != cookie && *(ptr - 1) == ' ') {
    strncpy(tmpcookie, cookie, ptr - cookie - 2);   /* v9.7:802 */
    tmpcookie[ptr - cookie - 2] = 0;                /* v9.7:803 */
  }
  ...
}
```

Trigger sequence (two response lines from the server):

1. `Set-Cookie:   aaa=1` — three spaces after the colon. The parser consumes
   the marker `Set-Cookie: ` (one space), leaving two leading spaces in
   `str`. `cookie` becomes `"  aaa=1"`.
2. `Set-Cookie:  aaa=2` — two spaces after the colon, leaving one leading
   space. `tmpname` becomes `" aaa="`, which matches the jar at index 1.
   Therefore `ptr - cookie == 1`, `*(ptr - 1) == ' '` (the jar's index-0
   space), and `ptr - cookie - 2 == -1`.

Consequences in v9.7:

- `strncpy(tmpcookie, cookie, (size_t)-1)` passes a negative length to libc;
  ASan intercepts it as `negative-size-param: (size=-1)`. With a short jar,
  glibc would copy just the jar bytes up to its NUL, so this call alone does
  not guarantee an overflow of `tmpcookie[4096]`.
- `tmpcookie[-1] = 0` writes a single NUL byte immediately before the
  stack buffer. That is the actual out-of-bounds write reached in this lab.
- The advisory's "overflows tmpcookie and crashes Hydra" is a coarsening:
  the reachable corruption is a one-byte stack **underflow** with a fixed
  value, not an attacker-length overflow. This matters for rung 4.

Fix commit `6ab9ad86` changes two things:

```c
-          *(++ptr) = 0;
+          if (ptr) *(++ptr) = 0;
...
-              strncpy(tmpcookie, cookie, ptr - cookie - 2);
-              tmpcookie[ptr - cookie - 2] = 0;
+              ssize_t off = ptr - cookie - 2;
+              if (off > 0) {
+                size_t n = (size_t)off;
+                if (n >= sizeof(tmpcookie)) n = sizeof(tmpcookie) - 1;
+                strncpy(tmpcookie, cookie, n);
+                tmpcookie[n] = 0;
+              }
```

The `off > 0` guard removes both the negative length and the negative index;
the `ptr` guard also removes a NULL dereference when a repeated-cookie line
has no `=` (not exercised here). Both hunks are in the same fix commit but
are distinct failure modes; this brief claims only the negative-offset path.

## 3. Laboratory reproduction

All work is under `lab/frontier/hydra2shell/`. Pins and harness sources are
tracked; upstream clones/worktrees, binaries and raw `.out` logs are ignored
and rebuild from the pinned commits.

Two lanes were run:

1. **Direct call.** Verbatim pinned function bodies
   (`src/analyze-v9.7.c`, `src/analyze-fixed.c`) are included by
   `harness/harness.c`, which supplies only the globals/helpers the function
   needs. Modes: `attack` (the two lines above), `single`, `normal`.
   `harness/build.sh` builds gcc and clang ASan/plain variants;
   `harness/run-all.sh` runs the matrix, records rc and the first ASan error,
   and writes `evidence/matrix.log` + its sha256.
2. **Real process over a real wire.** `v9.7` was built with ASan; a
   loopback-only Python server (`harness/loopback_server.py`) serves the two
   crafted headers to `hydra ... http-post-form` against `127.0.0.1`.
   The fixed commit was built the same way as a control, and the vulnerable
   binary was rerun against a benign one-cookie response.

Observed:

| Lane | Input | Result |
| --- | --- | --- |
| gcc ASan direct call | attack | `AddressSanitizer: negative-size-param: (size=-1)` at `src/analyze-v9.7.c:66`, rc 1 |
| clang ASan direct call | attack | same error, rc 1 |
| gcc/clang ASan direct call | single / normal | rc 0, no ASan error |
| gcc/clang ASan direct call, fixed blob | attack | rc 0, no ASan error; jar `" aaa=2"` |
| gdb, plain direct call | attack | at `src/analyze-v9.7.c:67`, `ptr - cookie == 1`, `*(ptr-1) == 0x20`; sentinel byte at `tmpcookie-1` changed `0x41 -> 0x00` across the write |
| ASan v9.7, real loopback HTTP wire | crafted headers | `negative-size-param (size=-1)` at `hydra-http-form.c:802`, called from `start_http_form:1062` ← `service_http_form:1354` ← `service_http_post_form:1391` |
| ASan fixed commit, same wire | crafted headers | rc 0, no ASan error |
| ASan v9.7, same wire | one benign `Set-Cookie` | rc 0, no ASan error |
| plain v9.7, same wire | crafted headers | rc 0, completes normally — **no crash** |

`evidence/matrix.log` sha256:
`57e16bfd9467d8b5ee2a8364b3c1e2cd809fee44e80c3751579dc2d4d108567b`
(PID-normalized, stable over repeated runs). Full raw traces are in
`evidence/*.out`; pin hashes are in `harness/PINS.sha256`.

## 4. Honest ceiling and feasibility

**Reached:** rungs 1-3 with attacker-controlled wire headers in a real v9.7
process (ASan-confirmed memory error) plus a direct-call observation of the
one-byte NUL write. The wire reachability is stronger than the direct call:
`http-post-form` parses the server's headers in the vulnerable function.

**Not reached:** rung 4 in the plant's sense. The OOB byte is always NUL and
the offset is always `-1`; there is no attacker-chosen byte, no chosen
offset, no live-object retargeting, no pointer/IP, no command, no witness and
no rung 5. The plain process does not crash, so the advisory's availability
claim is not reproduced here. A stack-adjacent object that is sensitive to a
single NUL byte at that exact offset was not found; the fixed and safe
controls stay clean.

**Cheapest next experiment that could move it up a rung:** map the plain
build's stack layout around `tmpcookie[-1]` across hydra module entry points
and compiler flag sets, then look for a call path where that byte is a
canary/length/pointer low byte. This is a narrow, low-yield search; the
primitive carries no attacker-selected data, so even a hit would be a
fragile one-byte corruption, not chosen-byte control. Not recommended ahead
of candidates with a real length/size mismatch.

**Disposition:** record as a screened-out rung-3 candidate with a brief; no
dedicated window, no admission request. Operator owns any reversal.

## 5. Preservation / negative results

- The prior frontier wake (attempt 329, no yield) left only the uncommitted
  busybox admission registration and the upstream hydra clone; this wake
  committed the former as `a8e3406` and used the latter. Its scout agents
  had no live session and their output was not recoverable.
- The first direct-call run returned rc 1 with no ASan report because the
  harness's `cond` stub was an empty string, making the function's success
  match fire on the first line. Fixed to a nonmatching sentinel; the attack
  then reached the bug.
- A plain hydra build with stack protector completes the crafted request
  without crashing. Preserved as a negative; no retry into existence.
- A gdb attempt to inspect the NUL write inside the real forked hydra worker
  (`set follow-fork-mode child`, breakpoint at v9.7 `hydra-http-form.c:803`)
  attached to the child but did not hit the breakpoint within 90 seconds and
  was killed (rc 124). The direct-call gdb observation remains the only
  byte-level proof; no forced wire-process byte observation is claimed.
- No external probe, no off-loopback target, no exploit framework, no
  witness claim.
