# shairport2Shell — frontier brief

**Candidate:** shairport-sync RTSP unrecognised-method hex-dump stack overflow,
GHSA-6g79-wrcj-h8xw (no CVE assigned). **Status:** local rungs 1/2/3 established
on verbatim pinned upstream `rtsp.c` bytes; rung 4 is instrumented chosen-byte
control at chosen offsets in harness stack storage only. No live daemon, no
socket, no pointer control, no execution. **Ranking:** high tractability —
pre-auth, network-facing, two-byte-per-input length error with a real fix commit
and both release pins — but the advisory claims availability only
(`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`, CWE-121, High 7.5). The honest ceiling
is a daemon crash unless a consumer-specific path turns the hex bytes into
control.

## Verified ground truth

- Maintainer advisory GHSA-6g79-wrcj-h8xw, published 2026-09-04 by
  `mikebrady`, `https://github.com/mikebrady/shairport-sync/security/advisories/GHSA-6g79-wrcj-h8xw`.
  Affected `< 5.5`; patched `5.5` and `5.6-dev`. CWE-121, CVSS 3.1 7.5,
  `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`. "No known CVE". Credit: @haavar.
- Claim: an AirPlay-2 receiver accepts an RTSP request whose method is not in
  `method_handlers[]`. The conversation thread hex-dumps the request body into
  a fixed 4096-byte stack buffer. The length is clamped to 4096 **bytes** but
  each byte becomes two hex characters plus a final NUL, so up to 8193 bytes
  are written. The fill loop runs regardless of log verbosity; on AirPlay 2 a
  fresh connection defaults to `airplay_type = ap_2`, which the advisory says
  bypasses the RTSP authentication check. The advisory's PoC is an unrecognised
  method with `Content-Length: 4096` and a 4096-byte body. We reproduce the
  write primitive locally; the auth-bypass claim is advisory text, not a live
  observation here.
- Fix history: development PR #2263 merged 2026-08-26
  (`74d59d8f83538c03852d51f953a2ca7716340fc2`); backport PR #2267 merged to
  `master` 2026-08-31 (`a5d8f46a54c0440bdd5290d385fe8a740c636d36`). Both URLs
  and commit metadata are in `lab/frontier/shairport2shell/PROVENANCE.md`.

## Source-bound mechanism

Pinned affected bytes are fix-parent `a50f18469143b9dbe599b8333d228a586dc29e67`;
fixed bytes are fix commit `c1c41c4ec9937eb7d2f8819dadd5bc45f65ab3f4` (one
parent, touches only `rtsp.c`). In `rtsp.c:4206-4221`:

```c
int y = req->contentlength;
if (y > 0) {
  char obf[4096];                       /* line 4208 (affected) */
  if (y > 4096)
    y = 4096;                           /* clamps BYTES, not hex chars */
  char *p = req->content;
  char *obfp = obf;
  int obfc;
  for (obfc = 0; obfc < y; obfc++) {
    snprintf(obfp, 3, "%02X", (unsigned int)*p);   /* line 4215 */
    p++;
    obfp += 2;
  };
  *obfp = 0;                            /* up to obf[8192] */
  debug(dl, "Content: \"%s\".", obf);
}
```

A 4096-byte body therefore writes 8192 hex characters plus a NUL into 4096
bytes: 4097 bytes past the buffer. The fix changes only line 4208 to
`char obf[2 * 4096 + 1]; // two hex chars per input byte, plus a terminating nul`;
the loop and the debug call are untouched. Tag `5.5` carries the fixed
declaration; tags `5.2.3` and `5.4-dev` carry the small one. A second, commented
copy of the same pattern at `rtsp.c:3478` is not the live network path and was
not exercised.

## Local evidence (verbatim pinned block)

Harness `lab/frontier/shairport2shell/`. `run.sh` checks both pinned sha256
values, asserts the exact lines and line numbers, then extracts lines
4206–4221 verbatim from each pinned file with a `#line 4206 "rtsp.c"` directive
and compiles one driver that executes those exact statements. Clean replay:
21 PASS, `ALL CHECKS PASS rc 0`, trace SHA-256
`b87176f5891ef547eef69a11176fd3e0a3a3c367fd19fdf80d30fa9b733e9c86`.

- **Rung 1** — 4096-byte body with an unrecognised method; the pinned block
  clamps `y=4096` and writes `obf_written=8193` bytes into `obf[4096]`
  (`expected overflow 4097 bytes`). Line numbers verified at `rtsp.c:4208` and
  `:4215`.
- **Rung 2** — a 512-byte harness stack object placed before `obf[]` records
  `first_changed=0`: the first byte past `obf[4096]` is written. The snapshot is
  taken inline before any further call because a later `printf` frame reuses
  the dead callee stack (observed and corrected during harness development).
- **Rung 3** — ASan reports `stack-buffer-overflow`, `WRITE of size 3` at the
  first `snprintf` past the end, frame `hexdump_unrecognised` at the real pinned
  `rtsp.c:4215`, and names `obf` as the overflowed stack object. No chosen-byte
  control is claimed from this ASan run (redzones).
- **Rung 4** — the body carries the token-safe marker `INDI2SHELL` at a computed
  index so its hex encoding `494E4449325348454C4C` lands at requested victim
  offsets 0 and 64; both read back byte-exact (`chosen_offset` equals the
  request). **INSTRUMENTED only:** the target is harness stack storage; the hex
  bytes are attacker-chosen within a token-safe alphabet; no live process, no
  return-address control, no execution.
- **Fixed control** — pinned `c1c41c4`: same 4096-byte input,
  `first_changed=-1`, chosen bytes absent, behaviour bounded to 8193 bytes.

## Rung-4 feasibility and cheapest next experiment

Reaching demonstrated impact needs a live `--with-airplay-2` build and an RTSP
client on loopback: send `FOOBAR rtsp://127.0.0.1/ RTSP/1.0` with
`Content-Length: 4096` and a 4096-byte body to the daemon's RTSP port, confirm
pre-auth reachability (no `Authorization`, fresh connection), and observe the
crash in stock and ASan builds. That is the cheapest rung-1/2 step on the real
consumer. For rung 4, determine whether the overflowing hex string can reach a
saved return address or a useful pointer on the actual compiled
`rtsp_conversation_thread_func()` frame: the compiled stack layout, not the
synthetic harness, decides whether this is a DoS-only finding. The advisory's
own claim is `A:H` only; no RCE is asserted.

## Scope and provenance

Claim text, fix PRs, pinned commit URLs, file hashes and extraction details are
in `lab/frontier/shairport2shell/PROVENANCE.md`. All network reads were
read-only provisioning of advisory and source bytes; no external host was
probed. The harness runs entirely in-process with no daemon, socket or external
connection. Witness should replay `bash lab/frontier/shairport2shell/run.sh
<outdir>` from a clean `git archive HEAD` and compare the trace hash.
