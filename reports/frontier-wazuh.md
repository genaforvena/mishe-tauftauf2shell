# frontier — Wazuh analysisd FIM alert heap overflow (wazuh2shell)

Status: **STAGED 2026-11-22 02:00Z**, not yet admitted. Rung 3 confirmed on
verbatim pinned upstream function bodies; rung 4 harness-level with a chosen
JSON byte observed in an adjacent heap object. Wire reach, live daemon crash
and rung 5 remain UNKNOWN. The advisory itself explicitly disclaims RCE.

## Verified ground truth

- Claim sources: NVD `CVE-2026-74045` (`src/CVE-2026-74045.json`) and GitHub
  advisory `GHSA-gc4j-j9fg-4cfr` (`src/GHSA-gc4j-j9fg-4cfr.html`), both
  reached as read-only provisioning; secondary VulnCheck advisory and the
  v4.14.8 release notes are cited in `lab/frontier/wazuh2shell/PROVENANCE.md`.
- Severity as claimed: High 7.1,
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:H/SC:N/SI:N/SA:N`, CWE-122.
- Affected: `wazuh-manager >= 3.12.0, < 4.14.8` (evidence-backed lower bound
  4.0.0 in the advisory). Patched: 4.14.8. Both defect halves are unchanged
  between the pinned v4.14.6/v4.14.7 tags per the advisory; frontier pinned
  v4.14.7 (affected) and v4.14.8 (fixed) raw sources by SHA-256.
- Claimed primitive: `snprintf(lf->full_log, OS_MAXSTR, ...)` in
  `fim_generate_alert()` writes a generated FIM alert whose length is derived
  from the event's *fields*, while `full_log` was allocated from the *input
  line* length in `cleanevent.c` as `2*strlen(pieces)+3`. A compact
  `registry_value` modification with no `old_attributes` expands
  `9e18` → 19 digits and emits the "changed from" comment strings, so a
  228-byte input yields a 459-byte allocation and a ~527-byte write.
- Claimed reach: an enrolled agent sends one crafted syscheck event through
  the encrypted 1514 channel to `wazuh-analysisd` running as root on the
  manager. The advisory reports a deterministic fleet-wide detection outage;
  it states control-flow hijack was **not** developed and does **not** claim
  RCE. A related but distinct bug, `CVE-2026-34150`
  (`json_extended.c::W_JSON_ParseRootcheck`, fixed 4.14.5), is not this lane.

## Source-bound mechanism (pinned bytes and fix hunk)

1. `cleanevent.c:59-62` (identical at v4.14.7 and v4.14.8):
   `loglen = strlen(pieces) + 1; os_malloc((2 * loglen) + 1, lf->full_log);`.
2. `fim_fetch_attributes_state()` (`syscheck.c:1753-1836`) maps JSON
   numbers `size`, `inode`, `mtime` through `w_long_str()` and JSON strings
   through `os_strdup()`, filling `lf->fields[]`. With no `old_attributes`,
   every `*_BEFORE` field stays NULL.
3. `fim_generate_alert()` (`v4.14.7:1603-1618`) builds twelve "changed from"
   comment strings because each before/after pair differs; the sink at
   `v4.14.7:1680` passes `OS_MAXSTR` (65536) as the size of `full_log`
   although the real allocation is 459 bytes. Nothing reallocates on this
   path before the sink; `fim_send_db_save()` is called only afterwards.
4. The v4.14.8 fix (`syscheck.c:1688-1723`) formats the same template into a
   local `char alert[OS_MAXSTR]`, then `free(lf->full_log);
   os_strdup(alert, lf->full_log); lf->log = lf->full_log;` and clears
   aliasing predecoder pointers. The allocation in `cleanevent.c` is
   unchanged: this is a missing output-sized copy, not an input-validation
   change.

## Local experiment actually run

Direct-call harness on verbatim upstream function bodies extracted by
signature from the hash-pinned v4.14.7/v4.14.8 `syscheck.c` (four functions;
`harness.c` stubs only surrounding types, allocator macros and two helpers
not on the write path). Full pins, build commands and raw logs:
`lab/frontier/wazuh2shell/PROVENANCE.md`.

- v4.14.7, advisory-derived JSON (228 bytes, `hash_sha256` set to `Q` at the
  same length): ASan `heap-buffer-overflow`, `WRITE of size 528`, 0 bytes
  after the 459-byte `full_log` region, frame `fim_generate_alert` →
  `run_case` → `main`. Stable trace: `out-direct/trace.txt`.
- v4.14.7 control with full `old_attributes` (406-byte input, 815-byte
  allocation): rc 0, 93-byte output, no ASan report.
- Plain v4.14.7 build with a 128-byte heap neighbour allocated immediately
  after `full_log`: neighbour goes from all `Z` to `: 'Q'` — an
  attacker-chosen byte from the JSON lands beyond the allocation. Plain
  control leaves the neighbour unchanged.
- v4.14.8 exploit and control: rc 0, no ASan report; plain v4.14.8 exploit
  leaves the neighbour unchanged. Sizes are identical across tags, so the
  fixed behaviour is attributable to the sink change.

This is **rung 3** on real upstream bytes (the sink, field mapping and
comment construction are verbatim) and **rung 4 at harness level** (chosen
byte at a chosen offset in a neighbouring heap object). It is not a live
daemon, not a wire-triggered fault, and not a pointer-control or
control-flow-hijack demonstration. Recoverable ASan redzones were not
treated as adjacent-object control; the placed-byte claim comes from the
separate plain build.

## Honest rung-4/wire assessment

- Wire rung 3/4 UNKNOWN here. The advisory's enrolled-agent 1514 replay and
  A/B daemon crash are claims; frontier did not build or run
  `wazuh-analysisd`, enroll an agent or send a message. No external system
  was contacted.
- The known content control is a byte chosen from a JSON field, not an
  arbitrary pointer and not a chosen address. A handful of events may crash
  the daemon per the advisory's claim, but that claim is not independently
  replayed.
- No benign marker execution, no command execution, no rung 5. The plant's
  rung-5 bar is a wire-triggered live target executing a lab-chosen benign
  command with observed side effect and vulnerable/fixed/safe-input
  controls; none of that exists here.

## Cheapest next experiment to move up a rung

1. Build `wazuh-analysisd` v4.14.7 from the pinned source on loopback,
   feed the exact advisory JSON through its local queue, and observe the
   same ASan frame or deterministic crash in the real daemon; repeat with
   the full-`old_attributes` control.
2. If the daemon path is reachable, enrol a local agent and replay over the
   encrypted 1514 channel. That would move wire reach from UNKNOWN to
   observed and give the target mind a live rung-4 starting point.
3. Repeat both against v4.14.8. Do not infer RCE from a crash; any rung-5
   work requires a measured pointer/consumer route first.

## Why ranked tractable

Open source, exact affected and fixed tags, a small and well-understood
fix, a public PoC with exact byte counts, and a server-side component with
an authenticated network path. The direct-call sink reproduces the claimed
write with matching sizes, so the main uncertainty is the live build and
wire setup, not whether the defect exists. No `wazuh*` charter, wall or
report existed before this brief; no admitted target overlaps this lane.
