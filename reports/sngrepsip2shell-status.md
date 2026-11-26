# sngrepsip2shell — admitted status (W298, 2026-11-26)
Admitted by the operator at 23:3xZ under standing #6 as the 193rd declared
target mind: claim source CVE-2026-121943 (CNA VulnCheck, published
2026-11-04), CWE-170, CVSS 6.3 v4.0 / 4.8 v3.1, affected `<= 1.9.0`; upstream
issue #589 is a static-only finding and PR 591 merged 2026-11-06 as
`d49c96c99bfff47b41c547113cb3a39dfb9b8717`, changing two stack buffers to
`MAX_SIP_PAYLOAD + 1` and two `memset` calls to `sizeof(payload)` (fixed pin is
the merge commit, not a numbered release). Claimed primitive: a 10240-byte
non-NUL SIP payload passes the unchanged `plen > MAX_SIP_PAYLOAD` guard and
leaves the stack array unterminated, so `regexec()`'s `strlen` reads one byte
past it. No duplicate CVE, GHSA or sink lane; the staged two-pane window 201
was adopted as-is (panes %408/%409, dead=0, one registry entry, 202/202 unique
names). The independent witness replay is owed; author reports are not
self-acceptance.

Rung-4 feasibility / named depth experiment under standing #7: build pinned
`v1.9.0` sngrep with ASan and the PR-591 merge as control, replay a locally
generated pcap or a loopback UDP SIP payload of exactly 10240 non-NUL bytes
for a real-consumer vulnerable/fixed differential (rung 2). For rung 4 in the
extracted harness only, place a live sentinel object immediately after
`payload` in the sink frame, print its bytes after `regexec()` and check for
attacker-chosen bytes at chosen offsets; ASan redzone readback does not count.
Resolve why the plain build exits 0 before claiming crash reachability. Never
promote a stack OOB READ or harness marker to a remote command execution claim.
Registered grade R1 — / R2 — / R3 ✓ / R4 — / R5 —; R4/R5 NOT CLAIMED.
Witness verdict not yet folded; `established=false` in the manifest.

## Operator clean-archive admission replay (23:35Z)

From `git archive HEAD lab/frontier/sngrepsip2shell` with `runs/` and four
prebuilt binaries removed: four pins sha256sum OK, runner sha256
`a4ebf8f62e9b8f4db2d4346911a059f51dc16231595b3409e016b71b03a9b819`,
`sh run-all.sh` rc 0, `PASS=13 FAIL=0`. Fresh GCC `-O1` ASan:
`stack-buffer-overflow`, `READ of size 10241` at verbatim raw `src/sip.c:338`
in `sip_validate_packet`, frame `[128, 10368) 'payload' (line 320)` accessed
at offset 10368 (exactly zero bytes past the 10240-byte array); clang `-O1`
reproduces at `:338`. Fixed pin on 10240 prints `SIP_VALIDATE_RC=0` with no
ASan; safe 10239 is clean on the vulnerable pin; 10241 is rejected by the
unchanged guard; plain vulnerable build prints `SIP_VALIDATE_RC=0` and exits 0
(rung 1/2 negative preserved). The generated sink slices are asserted
byte-for-byte against raw pinned lines 316-341 by the runner.
