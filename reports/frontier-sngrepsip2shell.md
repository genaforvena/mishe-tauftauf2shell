# Frontier brief: sngrepsip2shell — CVE-2026-121943 (unterminated 10240-byte SIP payload, stack OOB READ)

**Status: STAGED 2026-11-26 W298 — rung 3 ASan-confirmed stack-buffer-overflow
READ of size 10241 at verbatim pinned `src/sip.c:338` from the 10240-byte
`payload` array at `:320`.** Rung 1 and rung 2 NOT CLAIMED (plain build exits
0); rung 4 and rung 5 NOT CLAIMED (no chosen-byte readback, adjacent live
object, pointer, wire path or command). Claim sources are attributed below;
pinned bytes and observations are this plant's own. The witness re-runs any
published claim; the operator owns admission under standing #6. Frontier owns
no further work after handoff.

## Verified ground truth (claim sources read 2026-11-26)

- **Claim sources:** canonical CVE record
  `https://cveawg.mitre.org/api/cve/CVE-2026-121943` (CNA VulnCheck, reserved
  and published 2026-11-04, `datePublic` 2026-10-21), upstream issue
  `https://github.com/irontec/sngrep/issues/589` (opened 2026-10-21, closed
  2026-11-09), fix PR `https://github.com/irontec/sngrep/pull/591` (merged
  2026-11-06T08:53:29Z), CVE technical-description link to
  `https://github.com/irontec/sngrep/blob/v1.9.0/src/sip.c#L396-L410`. The
  CNA third-party HackMD write-up is tagged `exploit` in the CVE record; a
  direct fetch of the CISA ADP variant returned HTTP 403 (negative preserved).
  The VulnCheck advisory URL guessed from the title returned HTTP 404
  (negative preserved); the canonical CNA record is authoritative here.
- **Versions:** affected `<= 1.9.0` (semver, CPE `versionEndIncluding 1.9.0`);
  fix merged to upstream `master` as `d49c96c99bfff47b41c547113cb3a39dfb9b8717`
  (PR head `ebff667a7aac4727fad08f767172770c0f3ce967`). No numbered fixed
  release was verified; the fixed pin is the merge commit, not a tag.
- **Claimed primitive:** CWE-170 (Improper Null Termination), CVSS 6.3 v4.0
  (`AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:L`) and 4.8 v3.1. A UDP/TCP SIP
  packet or offline pcap payload of exactly `MAX_SIP_PAYLOAD` = 10240 bytes
  with no zero byte passes the `> MAX_SIP_PAYLOAD` guard, fills the stack
  buffer with no NUL, and makes `regexec()`'s `strlen` scan past the array in
  `sip_check_packet` (`:398/:406/:407/:410`) and `sip_validate_packet`
  (`:327/:331/:332/:338`), plus `strdup()` on the INVITE path (`:749`). The
  issue reporter states the finding was confirmed **statically only** — no
  runtime PoC in the report. PR 591 claims a sanitizer build hits
  `stack-buffer-overflow` with a 10240-byte SIP packet and parses normally
  after the fix; that claim is reproduced locally below in an extracted
  harness, not in a full sngrep build.
- **Fix (source-bound):** PR 591 changes four lines: both
  `u_char payload[MAX_SIP_PAYLOAD]` declarations become
  `u_char payload[MAX_SIP_PAYLOAD + 1]`, and both
  `memset(payload, 0, MAX_SIP_PAYLOAD)` calls become
  `memset(payload, 0, sizeof(payload))`. The `> MAX_SIP_PAYLOAD` length guard
  is unchanged; the extra byte is the terminator for the boundary length.

## Source-bound mechanism (pinned bytes)

`pins/sip.c.vuln` is the verbatim `src/sip.c` blob at upstream tag `v1.9.0`
(SHA-256 `c195674a72b0223b669e8ef9b2fce0a01d6c4224dd6ea217acfb5cc757462b30`);
`pins/sip.c.fixed` is the verbatim file at merge commit `d49c96c9…` (SHA-256
`8c1a6e151f6570e28cc4e2053a6470379b2563271032c0e055d81460e082c9a6`). Also
pinned: `sip.h.vuln` (`131d8d61…`, raw `:47` `#define MAX_SIP_PAYLOAD 10240`,
`:50` `MAX_CONTENT_LENGTH_SIZE 10`) and `packet.h.vuln` (`6732959b…`). All four
hashes are in `lab/frontier/sngrepsip2shell/pins/PIN_HASHES.txt`.

In the raw pre-fix file `:320` declares the 10240-byte stack array, `:327`
rejects only `plen > MAX_SIP_PAYLOAD`, `:331` zeroes exactly 10240 bytes,
`:332` copies `plen` bytes, and `:338` passes the array as a C string to
`regexec()` with the pattern initialized at raw `:201`
(`^([A-Z]+ [A-Z]+:|SIP/2\\.0 [0-9]{3})`). At `plen == 10240` every array byte
is nonzero in the harness vector, so the terminator is absent. `gen_sink.py`
copies raw lines **316-341** byte-for-byte into `h/sink_{vuln,fixed}.cpp` with
`#line 316 "src/sip.c"`; each generator run asserts raw `:320/:327/:331/:332/:338`
before slicing. `run-all.sh` independently re-checks that the generated body
contains the pinned slice. Types, the `calls` regex global, the driver and the
buffer-filling code are frontier scaffolding in the header/footer, explicitly
marked as such; they are not upstream source.

The wired path claimed by the advisory (`sip_check_packet` via live capture or
offline pcap, or `sip_validate_packet` via TCP reassembly) is **not**
harnessed. Only `sip_validate_packet` is called, directly from a local argv-
sized payload. No `sngrep` binary, libpcap capture, socket or pcap file is used.

## Local observation (2026-11-26 W298, GCC and clang ASan, loopback-free)

Vectors are local buffers of `A` bytes (no NUL): 10240 (boundary attack),
10239 (safe), 10241 (guard rejects). `sh run-all.sh` **PASS=13 FAIL=0** at
23:15Z (`runs/run-all.log`), rebuilding all four binaries from the generated
TUs.

- GCC 13.3 `-O1` ASan on 10240 (`runs/asan-vuln-10240.out`, rc 1):
  `AddressSanitizer: stack-buffer-overflow`, `READ of size 10241`,
  `regexec` → `sip_validate_packet(packet*) src/sip.c:338`; frame `[128, 10368)
  'payload' (line 320) <== Memory access at offset 10368 overflows this
  variable` — exactly zero bytes past the 10240-byte array.
- clang 18.1.3 `-O1` ASan reproduces `stack-buffer-overflow` at `src/sip.c:338`
  (`runs/clang-asan-vuln-10240.out`, rc 1).
- Fixed pin on 10240 parses cleanly (`SIP_VALIDATE_RC=0`, rc 0, no ASan);
  10239 is clean on the vulnerable pin; 10241 is rejected by the unchanged
  guard before the copy, also clean.
- Plain GCC build on 10240 exits 0 with `SIP_VALIDATE_RC=0`
  (`runs/plain-vuln-10240.out`). Preserved negative: no rung-1 crash and no
  rung-2 accounting/state failure observed.

Full pin provenance, URLs, fetch method, compiler versions and negatives:
`lab/frontier/sngrepsip2shell/PROVENANCE.md`.

## Rung-4 feasibility (honest)

- **Rung 1 and rung 2 NOT CLAIMED.** Plain build exits 0; no deterministic
  crash or corrupted state was observed outside ASan.
- **Rung 3 ASan confirmed** on the verbatim pinned `regexec` call, with GCC and
  clang; fixed, safe and oversize-guard controls clean.
- **Rung 4 NOT CLAIMED.** The harness prints nothing from past the buffer.
  ASan's poisoned redzone is not a neighbouring live object; no chosen byte,
  chosen offset, pointer value or control-flow effect was measured. The
  issue's "leak adjacent stack bytes into displayed SIP fields" remains a
  claim, not a local readback.
- **Rung 5 NOT CLAIMED.** No SIP wire path, pcap, capture thread, `sngrep`
  process, remote input or command was exercised.

## Cheapest local experiment that could move this up a rung

1. Build pinned `v1.9.0` sngrep with ASan (and the PR-591 merge as control),
   replay a locally generated pcap or a loopback UDP SIP payload of exactly
   10240 non-NUL bytes, and observe a vulnerable/fixed crash or parse
   differential. That is rung 2 through the real consumer, still not rung 5.
2. In the extracted harness, place a live sentinel object immediately after
   `payload` in the sink frame, print its bytes after `regexec`, and check
   whether attacker-chosen nonzero bytes appear at chosen offsets. That is
   rung 4 in the extracted harness only; ASan redzone readback does not count.
3. Resolve why the plain build exits 0 (adjacent stack zero byte) before
   claiming crash reachability. Never relabel a stack OOB READ as RCE.

## Ranking note (W298)

W297 scouts identified sngrep CVE-2026-121943 (tractability 5) as a fresh
backup. Ground truth this wake showed a four-line upstream fix, a 10240-byte
boundary trigger, libc-only harness dependencies and a clean GCC+clang ASan
differential in minutes. VVdeC CVE-2026-124309 remains a lower-priority backup
because it needs a full decoder build and an external VVC bitstream PoC;
GHSA-w829-5g45-5g7q needs a full `PelStorage` context. No charter, wall, lab
directory or window for `sngrepsip2shell` existed before this wake, and it is
not in the frontier do-not-duplicate list. Ranked by measured local
tractability, not advisory severity.
