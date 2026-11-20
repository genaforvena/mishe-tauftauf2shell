# Node2Shell — status

Target: Node2Shell — CVE-2026-123828, one-byte heap overflow in HTTP/2
Alt-Svc handling, `src/node_http2.cc`: buffer sized to the origin length,
null terminator written one byte past the end. Remote unauthenticated
trigger: a single HTTP/2 request with a long syntactically valid
`:authority` that the application forwards to `session.altsvc()`.

Admitted by the operator 2026-11-20 under standing approval #6
(similar-things mandate; tape entry 2026-11-20T07:29:19Z).

- **Rung:** 2/3-class observation on stock glibc (1/6, not
  deterministic): `malloc(): mismatching next->prev_size (unsorted)`
  abort of stock node v20.20.2 after a single loopback request with
  `origin_len = 1048` (≡ 8 mod 16 — NUL hits the following chunk's size
  LSB). Deterministic rung-1/2 ASan differential on affected v24.22.2
  in flight (build detached, spans wakes).
- **Ground truth verified from primary sources:** fix commit
  `nodejs/node@ae9ab37d62` read as specification; vulnerable code
  present in tags v24.22.2/v26.13.0 (also v22.23.5 and v20.20.2 via the
  old V1 `WriteOneByte` default), absent verbatim in v24.22.3/v26.13.1.
  Snyk's "22.x fixed in 22.23.5" contradicted by tagged source — no
  backport in 22.23.5's `node_http2.cc` and its vendored V8 still
  null-terminates.
- **Next action:** when the detached ASan build of v24.22.2 completes
  (check `lab/build/node-24.22.2-asan.DONE` / build log), run the
  rung-1 harness against it (expect deterministic ASan
  heap-buffer-overflow WRITE of size 1); then apply the fix diff,
  incremental rebuild for the fixed control, and record the
  differential in reports/node2shell-investigation.md.
- **Last evidence:** first-wake abort log quoted in
  reports/node2shell-investigation.md (Evidence ladder section);
  harness lab/repro/node2shell-rung1-{server,client}.js.
- **Unknowns:** whether the detached build survives the wake boundary
  (checked next wake — restart from the log's last object if killed);
  whether the stock-glibc abort class can be groomed to determinism
  (Stage A, Ruby2Shell playbook); whether 22.x/20.x lines are worth
  their own ASan builds (low priority — official affected lines are
  24.x/26.x).
