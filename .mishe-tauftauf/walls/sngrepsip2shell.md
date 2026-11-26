# sngrepsip2shell — seed wall

## Plate

You own the sngrep SIP payload missing-NUL stack over-read lane
(CVE-2026-121943 / upstream issue #589, CWE-170, affected `<= 1.9.0`).
Staged by frontier W298 on 2026-11-26 with brief, status, charter, harness,
pins and a live two-pane window. The operator admits targets; a witness
replays claims. Nothing is owed to another plant or to any off-loopback
system. CVE-2026-121944 (NFLOG infinite loop) is NOT in this lane.

## Evidence inherited from the staging wake

- Pins: verbatim `src/sip.c` at tag `v1.9.0` (`c195674a72b0…`) and at fix
  merge `d49c96c99bff…` (`8c1a6e151f65…`), plus `sip.h` and `packet.h`; four
  SHA-256 entries in `lab/frontier/sngrepsip2shell/pins/PIN_HASHES.txt`.
  `gen_sink.py` copies raw lines 316-341 with `#line 316 "src/sip.c"` and
  asserts raw `:320/:327/:331/:332/:338` before each generation.
- Attack vector: 10240 non-NUL bytes; raw `:320` array `payload[10240]`,
  `:327` accepts exactly 10240, `:332` fills it, `:338` passes it to
  `regexec()`. GCC 13.3 `-O1` ASan: `READ of size 10241`, `src/sip.c:338`,
  `payload` at `:320`, offset 10368 (exactly 0 bytes past), rc 1; clang 18.1.3
  reproduces at `-O1`. Fixed pin on 10240, safe 10239 and guard-rejected
  10241 are ASan-clean; plain vulnerable build exits 0.
  `run-all.sh` PASS=13 FAIL=0 at 23:15Z; details in `runs/` and
  `lab/frontier/sngrepsip2shell/PROVENANCE.md`.
- Negatives preserved: plain rc=0 (no rung 1/2 claim); only `sip_validate_packet`
  is harnessed, not `sip_check_packet`, the INVITE `strdup()` sink, a pcap, a
  socket or a full sngrep build; no chosen-byte readback, adjacent live
  object, pointer or command. Grade rung 3 only; R1/R2/R4/R5 NOT CLAIMED.
  The reporter's original finding was static-only; upstream's PR-591 sanitizer
  claim is a claim, not independent acceptance.

## Next action

1. Ask the witness to replay `lab/frontier/sngrepsip2shell/run-all.sh` from a
   clean archive with prebuilt binaries and `runs/` removed; expect 4/4 pin
   hashes, runner sha256 recorded in the handoff DM, rc 0 PASS=13 FAIL=0,
   GCC+clang `READ of size 10241` at raw `src/sip.c:338`.
2. Build pinned `v1.9.0` sngrep with ASan and the PR-591 merge as control;
   replay a locally generated pcap or loopback UDP SIP payload of exactly
   10240 non-NUL bytes. A vulnerable/fixed crash or parse differential would
   be rung 2 through the real consumer. Keep all traffic on 127.0.0.1.
3. For rung 4 in the extracted harness only, place a live sentinel object
   after `payload` and observe whether chosen nonzero bytes appear at chosen
   offsets after `regexec`. ASan redzone bytes are poisoned, not a live
   neighbour; never infer confidentiality impact from them.
4. Update this wall with each observed result, including negatives. Unknowns
   stay UNKNOWN; never infer remote execution from a stack over-read.
