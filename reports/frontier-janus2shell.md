# Frontier brief — Janus2Shell (Janus Record&Play, GHSA-8qwr-6p52-4vj9)

## Verified ground truth (claims, not lab proof)

- Upstream advisory GHSA-8qwr-6p52-4vj9, published 2026-10-12 by the Janus
  maintainer, reporter AdamKorcz (advisory credits Anthropic and Ada Logics):
  <https://github.com/meetecho/janus-gateway/security/advisories/GHSA-8qwr-6p52-4vj9>.
  Title: a recording with an over-long codec string (`a=fmtp`) overflows a
  1500-byte buffer and crash-loops Janus. Advisory CVSS 3.1 **7.5**
  `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` — the advisory claims **availability
  impact only**; it explicitly says "No known CVE" (a targeted NVD 2.0 keyword
  query returned zero results).
- Affected `<= v1.4.2` and `<= 0.16.2`; patched `1.4.3` and `0.16.3`. The
  v1.4.3 CHANGELOG (2026-10-12) records "[SEC] Fix potential buffer overflow
  in Record&Play plugin (reported by AdamKorcz) [PR-3688]".
- Fix commits: `e55e2915a2801f18495c7f0d049af9274dd70065` (1.4.x) and
  `c31cad9768368b996aa68753df1656fe4f30af7e` (0.16.x), each adding exactly
  one five-line guard at two parsed-header sites in `janus_recordplay.c`.
  Patch: <https://github.com/meetecho/janus-gateway/commit/e55e2915a2801f18495c7f0d049af9274dd70065.patch>.
- Advisory reproducer: an unauthenticated WebRTC client records a session
  whose video `a=fmtp` is about 1900 bytes; the recorder writes a 1986-byte
  info header into the `.mjr` file; a later play request (and each startup
  rescan) reads that length into the fixed buffer, aborting the daemon
  repeatedly. Unauthenticated remote reachability is the advisory's claim;
  this brief does not exercise it.

## Source-bound mechanism

At tag `v1.4.2`, `src/plugins/janus_recordplay.c:664` declares
`char prebuffer[1500]`. In both `janus_recordplay_parse_codec()` (`:701-714`)
and `janus_recordplay_get_frames()` (`:2603-2617`) the new `.mjr` header path
reads a 16-bit big-endian info-header length and executes, with no bound:

```
bytes = fread(prebuffer, sizeof(char), len, file);   /* :707, :2610 */
...
prebuffer[len] = '\0';                               /* :714, :2617 */
```

`len` comes from file bytes the recording client influenced; the source has
no capacity check before either write. The fix inserts at both sites:

```
if(len >= sizeof(prebuffer)) {
        JANUS_LOG(LOG_ERR, "Info header too big (%"SCNu16" bytes), invalid recording\n", len);
        fclose(file);
        return NULL;
}
```

Same shape on the legacy branch: `plugins/janus_recordplay.c:705/712` at
`v0.16.2` (vulnerable) and `:705` at `v0.16.3` (guarded). The v1.4.3 fix does
not clamp the separate playout-thread frame reads (advisory-side caveat from
the scout); that half is outside this harness and stays UNKNOWN.

## Local replay and observed rungs

Harness `lab/frontier/janus2shell/` executes the **verbatim pinned** header
parse blocks from `v1.4.2` (vulnerable, lines 669-670 and 701-714) and
`v1.4.3` (fixed, lines 669-670 and 701-719) under `#line` directives. The
`.mjr` byte stream is synthetic and in memory (`fmemopen`); collaborators are
stubs. No Janus process, HTTP API, SDP parser, real recording, socket or
network. Full pin hashes and boundary in `PROVENANCE.md`.

Working-tree replay, 2026-11-21: **29 PASS / 0 FAIL**, trace
`sha256=c8568d26b07cac408da640b7e6d8347d1c43db3119274fafbfb73f3e41f9a21f`
(two consecutive replays byte-identical).

- Rung 1 — deterministic trigger: a benign 100-byte header writes 100 bytes,
  `overflow=0`; the chosen 1986-byte header writes 1986 bytes into
  `prebuffer[1500]`, `overflow=486`. The length is the advisory's own header
  length and fits the pinned 16-bit field.
- Rung 2 — accounting failure: the vulnerable build accepts the oversized
  header (`rejected=0`, normal return path) while the `v1.4.3` guard rejects
  the same bytes (`REJECT mode=chosen rejected=1`, `Info header too big
  (1986 bytes)`) and still accepts the benign header.
- Rung 3 — ASan confirms corruption: `stack-buffer-overflow`, `WRITE of size
  1986` at the pinned `fread`, frame `src/plugins/janus_recordplay.c:707`;
  nonzero rc. ASan places `prebuffer` at `[64,1564)` in this frame.
- Rung 4 — INSTRUMENTED only: in the lab frame the 16 bytes at
  `prebuffer+1500..1515` equal the chosen `.mjr` payload bytes
  (`CHOSEN_MATCH=1`, `53 54 55 56 57 58 59 5a 41 42 43 44 45 46 47 48`);
  the adjacent local `len` is overwritten to `0x5453` (the first two chosen
  bytes past the array, `ADJACENT_LOCAL_OVERWRITTEN=1`); a second build with
  the host compiler's default stack protector aborts with `stack smashing
  detected`. No pointer, saved return address value, control-flow diversion
  or benign marker execution was claimed or attempted. The canary abort is
  evidence of control-data adjacency in *this* compiled frame only.

## Feasibility and cheapest next rung

Tractability for rungs 1-3 is high: two small pinned blocks, a plain `fread`
into a stack array, a two-line guard, and both release pins verified. Rung 4
beyond INSTRUMENTED is UNKNOWN: the advisory rates availability only and no
published claim asserts code execution. Shipping compiler flags, stack canary
settings, allocator/layout and the real HTTP-to-`.mjr` path were not
exercised; the recording-to-playback chain is the advisory's claim.

Cheapest next rung: start a stock `v1.4.2` Janus bound only to 127.0.0.1 with
Record&Play enabled, create the recording through the documented HTTP API
with an ~1900-byte `a=fmtp`, then request playback under ASan (and a separate
non-ASan run with a debugger watching the saved return address). Capture the
wire bytes, the produced `.mjr` header, the real ASan frame and the post-write
stack state; repeat with `v1.4.3`. Only a pointer/control-flow observation
would justify dropping the INSTRUMENTED label; otherwise preserve the
availability-only characterization.

All ground-truth items in the first section remain claims reproduced from
public sources; this brief proves the pinned code path and its memory effect,
not advisory reachability, severity or exploitability.
