# Node2Shell — status

Target: Node2Shell — CVE-2026-123828, one-byte heap overflow in HTTP/2
Alt-Svc handling, `src/node_http2.cc`: buffer sized to the origin length,
null terminator written one byte past the end. Remote unauthenticated
trigger: a single HTTP/2 request with a long syntactically valid
`:authority` that the application forwards to `session.altsvc()`.

Admitted by the operator 2026-11-20 under standing approval #6
(similar-things mandate; tape entry 2026-11-20T07:29:19Z).

- **Rung:** 3/3.5 — confirmed corruption with two independent one-byte
  terminator writes; rung 4 NOT demonstrated. On officially affected
  v24.22.2 a single unauthenticated loopback request with
  `origin_len=1048` (≡ 8 mod 16) aborts stock glibc on the first
  request **10/10** (`malloc(): invalid size (unsorted)`, rc 134);
  Memcheck on the same prebuilt reports `Invalid write of size 1` in
  `WriteOneByteV2` **2/2**, with fixed v24.22.3 clean. Wake 33 isolated
  the value/ALT terminator as a second trigger (ALT 1048 → 4/4 then
  3/3 SIGABRT `malloc(): invalid next size (unsorted)`; off-class
  controls 2/2 each alive with the ALTSVC echo). Wake 34 combined both
  on-class writes: 8/8 aborts across three glibc signatures, origin
  write dominating, no new primitive. In the completing regime the NUL
  persists in the top chunk's sizefield while the ALTSVC echo is still
  served (rung 3.5). The first-wake 1/6 abort on EOL v20.20.2 remains
  in the report as the historical, layout-dependent observation.
- **Ground truth verified from primary sources:** fix commit
  `nodejs/node@ae9ab37d62` read as specification; vulnerable code
  present in tags v24.22.2/v26.13.0 (also v22.23.5 and v20.20.2 via the
  old V1 `WriteOneByte` default), absent verbatim in v24.22.3/v26.13.1.
  Snyk's "22.x fixed in 22.23.5" contradicted by tagged source — no
  backport in 22.23.5's `node_http2.cc` and its vendored V8 still
  null-terminates.
- **Next action:** none on the current primitive; hold. A fake `prev_size`
  needs seven consecutive NUL bytes, no remote HTTP/2 string channel
  carries NUL (UTF-16 low-byte truncation included), and the library's
  single terminator lands on the sizefield LSB, eight bytes too late.
  Act only on a genuinely new binary-heap-byte primitive or a
  free-preceding-chunk geometry with no later `!prev` free; a timestamp-
  only advisory check is not work. Do NOT re-run origin/value length or
  NUL sweeps. No timer: the trigger is a new witness message or a new
  primitive. The detached ASan build was killed at a wake boundary and
  abandoned; the Valgrind differential on official prebuilts replaced
  it and needs no build.
- **Last evidence:** full traces in reports/node2shell-investigation.md
  (evidence ladder, Stage A, wake 33/34 sections). Re-runnable checks:
  `sh lab/repro/node2shell-valnul/run.sh 3`,
  `sh lab/repro/node2shell-stageA.sh`, and the original harness
  `lab/repro/node2shell-rung1-{server,client}.js`.
- **Unknowns:** whether any rung-4 lane exists under a different
  allocator or consumer; external reachability beyond loopback (all
  testing here is 127.0.0.1 only); 22.x/20.x builds were not run
  (low priority — the official affected lines are 24.x/26.x).
