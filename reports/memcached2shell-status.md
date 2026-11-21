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
- Rung 4, chosen-byte limb ESTABLISHED AS CLAIMED (witness #751). In the
  harness a zeroed 1 MiB collaborator gives chosen `0x5a` at offsets 0, 4 and
  65536 past the nominal end (35231 of 65536 bytes matched), with an `0x41`
  differential at exactly those offsets; a guard-mapped allocation faults at
  the first byte past 131072 (exit 77). Those are instrumentation. The
  decisive evidence is in a real daemon: a non-perturbing `/proc` observer on
  a live non-instrumented build of the pinned parent sees chosen key bytes at
  `buf+131072` and at +512/+1024/+2048/+16384 as the write frontier advances;
  two key bytes (`0x5a` and `0x41`) at identical offsets and timing prove the
  bytes come from the stored key record. The witness replayed all of it
  independently (#710 rung 3, #751 chosen bytes) and accepted it as claimed.
  No pointer, saved return address, heap metadata field, function pointer,
  execution or control-flow diversion was observed or claimed.
- Conditional, not a grade basis: the chosen-byte overwrite of a
  pointer-shaped heap window at `buf+131072+16384` appeared in this plant's
  two traces and the witness's `0x41` replays, but the window was zero in two
  witness `0x5a` replays — allocator-state dependent and semantically
  unidentified. One prolonged run saw a non-deterministic daemon SIGSEGV in a
  slab-freelist pointer write in the crawler thread; a longer
  observer-confirmed repeat went further without crashing, so that fault is a
  single observation, not an established impact.
- New, submitted for witness replay (fifth wake): the pinned plain parent,
  run under gdb with no breakpoints and ASLR on, faults in
  `assoc_find` (`assoc.c:87`, `movzbl 0x29(%rbx)`) in three of four stress
  runs; with the chosen byte `0x5a` the hash-bucket chain
  item pointer equal to eight attacker-chosen `0x5a` key bytes
  (`0x5a5a5a5a5a5a5a5a` in two independent runs); a `0x41` run faults at the
  same site with a different attacker-written value, and the pinned fixed
  tree does not fault under the identical trigger (42,770 sets in 90 s).
  A fourth stress run and a non-stress run did not fault; crash timing is
  allocator-state dependent, and the frontier was not read in-run.
  A stress client drove the extra allocation pressure; all sockets were
  127.0.0.1. Raw captures and caveats:
  `reports/memcached2shell-daemon-asan.md`, fifth-wake section. This is a
  reproduced crash/DoS impact limb, not a crafted-address or execution
  result, and the grade stays ◐ pending independent replay.
- UNKNOWN: loopback socket-buffer timing outside this configuration, shipping
  allocator and compile flags of a distro binary, a published CVE/GHSA, CVSS,
  external reachability, canonical chosen-address control and control-flow
  diversion. The pinned `uriencode_p()` emits literal only alphanumerics and
  `-._~`, so a canonical pointer cannot be forged through the key path.
  All external claims remain claims. No probe was sent off loopback.

Grade reference: witness verdicts #691 (seed harness) and #751 (daemon
evidence) are ESTABLISHED AS CLAIMED. Only the chosen-byte limb of rung 4 is
accepted; pointer control, dereference, execution and control-flow diversion
are not. Full daemon evidence: `reports/memcached2shell-daemon-asan.md`.

Next: witness replay of the fifth-wake pointer-dereference evidence. The
remaining grade-moving result is a control-flow diversion or a canonical
crafted value demonstrably used through the corrupted field; another
unchanged 86 s replay or allocator probe would add nothing. No host config
change and no off-loopback probe. Wake trigger units and presentation stay
owed from the person-only full-flag sync in `docs/runtime-pin.md`, never a
bare `mishe sync`.
