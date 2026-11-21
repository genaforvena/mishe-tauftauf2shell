# memcached2shell — status

Admitted 2026-11-21 ~08:29Z by the operator under standing approval #6 on
frontier's handoff #686 and commits `b7fb237` / `163433e`, brief
[frontier-memcached2shell.md](frontier-memcached2shell.md). Claim source:
upstream fix commit
`7eeac6e9a9945aa68298aff379cea5ab3817af7c` ("crawler: fix buffer overflow on
idle client", 2026-07-07), parent
`aa352388abf903d50e6bdd22dfb8ab9373d2896b`, release 1.6.44 (target commit
`e44dd0b01234bc0faf970e9225e3423e98022129`), Ubuntu LP#2161693 and
openSUSE-SU-2026:21872-1. LP#2161693 records affected Ubuntu 1.6.24/1.6.40,
an unauthenticated stalled-reader reproducer on a default non-SASL instance,
and the upstream fix in 1.6.44. No upstream CVE/GHSA found; CVE/GHSA is
UNKNOWN / NO-CVE-FOUND, not a proven negative. Full upstream affected range
UNKNOWN. Pins, hashes, raw URLs and harness repairs:
`lab/frontier/memcached2shell/PROVENANCE.md`.

Claimed trigger: default config enables `lru_crawler` and `dump_enabled`
without an auth gate. After `lru_crawler metadump all`, an idle client fills
the socket send buffer; pinned `lru_crawler_write()` treats a `poll()` timeout
as success (`crawler.c:471`) without resetting `bufused`, and the per-LRU
caller at `:628-640` never expands the buffer as the hash path does. The
`crawler_metadump_eval()` appends attacker-stored key bytes at `buf + bufused`
(`:307-310`, `:371`) past the 131072-byte allocation at `:824-825`. The
unconditional `sent += total` at `:499` is a second, separately preserved
accounting defect. `-X` and `-o no_lru_crawler` are non-default mitigations.

- Harness: `bash lab/frontier/memcached2shell/run.sh` — 8 PASS / 0 FAIL,
  raw trace `sha256=5d4a05be6cebb89e7fd99e0f6d08731e47537c49d0b8396d6be73e554b51672b`.
- Operator replay ~08:28Z from two clean `git archive HEAD` (`163433e`)
  extractions into separate absolute directories: 8 PASS / 0 FAIL in both,
  raw trace
  `sha256=5d4a05be6cebb89e7fd99e0f6d08731e47537c49d0b8396d6be73e554b51672b`
  — byte-identical between directories, to the working-tree replay and to the
  brief.
- Rungs 1/2/3 on verbatim pinned parent (1.6.44-pre fix) and fixed `crawler.c`
  ranges: parent idle client exits 77 after ~1000 appended lines while the
  fixed build times out 1800 polls and closes the client; parent EAGAIN
  reports `write_ret=0` with zero bytes written while the fixed build returns
  -1; ASan reports `heap-buffer-overflow`, `WRITE of size 64`, 0 bytes after
  the 131072-byte region, append frame `crawler.c.vuln:310` and allocation
  frame `:825`, with clean fixed and benign-parent controls. The 64 bytes are
  a verbatim harness key; real `uriencode_p()` makes the write key-length
  dependent.
- Rung 4 INSTRUMENTED only, with preserved negatives. With a zeroed 1 MiB
  collaborator replacing the nominal buffer, chosen key byte `0x5a` is read
  back at offsets 0, 4 and 65536 past the nominal end (35231 of 65536 bytes
  matched); a differential `0x41` run puts `0x41` at exactly those offsets.
  Under a guard-mapped allocation the parent faults at the first byte past
  131072 (exit 77), and the unmodified plain parent faults in host libc
  before any stable chosen bytes can be inspected. No pointer, saved return
  address, heap metadata field, function pointer, control-flow diversion or
  marker execution was observed or attempted. The collaborator and guard
  mapping are instrumentation, not upstream allocator properties.
- UNKNOWN: live daemon, loopback socket-buffer timing, shipping allocator and
  compile flags, real daemon ASan frames (the LP recipe reports a frame at
  `crawler.c:275` on 1.6.24, a different build), CVSS, CVE/GHSA assignment,
  and any post-write pointer control. All external claims remain claims.
  Witness replay #685 was requested; no verdict was in hand at admission.
  No probe was sent off loopback.

Cheapest next rung: determine this host's actual consumer behavior at the
buffer boundary first (allocator layout, `write()`/`poll()` timing), then
build the pinned vulnerable tree under ASan, run a loopback-only daemon with
many stored keys, stall a `lru_crawler metadump all` client and capture the
real ASan frame plus the heap layout around the 131072-byte buffer; repeat on
1.6.44 for the guard. Only an observed pointer or control-flow result would
drop the INSTRUMENTED label. If the daemon's allocator faults before chosen
bytes persist, preserve that as the same real-libc negative and cap this path
at rung 3 in practice (the sibling nginx2root lesson applies).
