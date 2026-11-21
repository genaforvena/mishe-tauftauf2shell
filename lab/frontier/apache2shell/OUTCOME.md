# apache2shell local experiment — W91 (2026-11-21)

## Builds and pins

- httpd 2.4.70 and 2.4.71 release tarballs, SHA256 matched ASF
  (`1eefd7dc…afc3`, `2bc5da5a…de62`).
- nghttp2 1.59.0 built locally with `-fPIC`; APR 1.7.4 / APR-util 1.6.3
  built locally with `-fsanitize=address`; `ldd` confirms both httpd
  binaries link the locally built ASan APR/APR-util.
- Both builds instrumented at the one-line fix site with `ap_log_rerror`:
  2.4.70 logs `APACHE2SHELL_TRIGGER` at `req->headers`, 2.4.71 logs
  `APACHE2SHELL_FIXED` at `r->headers_in`. Instrumentation is a harness
  marker only; it does not change the allocation.
- Servers bound to 127.0.0.1 ports 18080/18081 (2.4.70) and 18082 (2.4.71),
  prefork, `Protocols h2c http/1.1`.

## Rung 1 ESTABLISHED — reproducible wire trigger

- With curl `--http2-prior-knowledge`, 76 custom headers + `Content-Type`
  and no `Content-Length` put the stream header table at
  `nelts=80 nalloc=80` — exactly the full-table condition under which the
  vulnerable `apr_table_setn()` grows the array and allocates from the
  connection's unlocked APR allocator. Sweep evidence: `nelts` 74→84 as
  header count 70→80, with `nalloc` jumping 80→160 at 81 entries.
- 300/300 and 2000/2000 curls reached the wrong-pool write on 2.4.70;
  400/400 reached the fixed write on 2.4.71.
- A multiplexed h2c driver (`repro-h2c-mux.py`, manual HPACK literals,
  78 regular headers per stream) produced 3015 full-table writes on 2.4.70
  and 13 on 2.4.71 across the runs.

## Rung 2/3 NOT established — negative and inconclusive results preserved

- 2000 separate-connection curls with full-table writes, ASan-instrumented
  APR: 0 ASan reports, 0 child crashes.
- One 2000-stream/10-connection multiplexed burst on 2.4.70 produced a
  single child `exit signal Segmentation fault (11)`
  (21:43:55Z, pid 2071101), with 1003 full-table writes in that window.
  This crash was **not reproduced** in a repeat burst (server degraded
  after the first) nor in a matched 300-stream/3-connection run
  (300/300 full-table writes, 0 crashes on either build). Rung 2 requires
  a deterministic crash; it stays UNKNOWN, not established.
- Matched clean restart run: 2.4.70 300 full-table writes / 0 crashes;
  2.4.71 300 fixed writes / 0 crashes; 0 ASan reports on both.
- Fixed-control traffic was heavier than the vulnerable repeat in one run
  (413 markers vs 5442 cumulative) and one probe timed out; that run is
  not used as a clean differential. The matched 300/300 run is the control.

## Interpretation

The wire path and the wrong-pool write are confirmed on the vulnerable
build. The allocator race is timing-sensitive under this host's APR and
traffic shape; no ASan corruption report was obtained. The single SIGSEGV
is a lead, not evidence of corruption. Chosen bytes at chosen offsets are
not given by this primitive (the written value is the fixed string "0").
Logs: `build/httpd-{2.4.70,2.4.71}-asanapr/logs/error_log`, `start*.err`;
driver outputs `out-burst*.txt`, `out-mux-*.txt`.
