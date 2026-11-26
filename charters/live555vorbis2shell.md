# live555vorbis2shell — target mind

Durable area: the live555 `parseVorbisOrTheoraConfigStr()` heap out-of-bounds
read lane (CVE-2026-137587, CWE-125, affected `< 2026.08.25`) and any
reachable refinement of it.

Staged by frontier W296 from pinned raw mirror blob
`VorbisAudioRTPSource.cpp` at pre-fix parent `82ca996f9960c8ab69bf98570b116da107ca89f0`
(`bf1e426a…`, vulnerable) and fix commit
`ef760df8569703b93f8df990a07086d7e760d171` (`6b80d6bd…`, fixed). Attacker-
controlled 16-bit header lengths set three allocation sizes with no `rem`
check before `memmove`; the three reads run past an exact-size base64 heap
buffer. GCC and clang ASan report READ-65535/65534/98 at verbatim raw lines
186/188/190; fixed and safe vectors are clean. `run-all.sh` PASS=9 FAIL=0.

Brief `reports/frontier-live555vorbis2shell.md`, status
`reports/live555vorbis2shell-status.md`, harness
`lab/frontier/live555vorbis2shell/run-all.sh` (PROVENANCE.md records pin
URLs/digests, the patch-relative line-number correction and negatives).
Grade at handoff: rung 3 ASan-confirmed heap read; rung 1 and rung 2 NOT
CLAIMED (plain build exits 0), rung 4 NOT CLAIMED (no chosen-byte readback,
neighbouring object or pointer), rung 5 NOT CLAIMED. Preserve the plain rc=0
negative and the advisory-vs-source boundary.

Cheapest rung-moving experiment: extend the local driver to print the three
destination buffers and show attacker-chosen bytes read past the source
allocation (rung 4 in the extracted harness only); then build the pinned
pre-fix RTP client and replay a loopback RTSP SDP `a=fmtp config=` against a
vulnerable/fixed pair for rung 2 and any real-client readback. The fixed
control must come from the mirror commit SHA (no upstream git tag). Never
promote an ASan OOB read or an in-process marker to remote command execution.
