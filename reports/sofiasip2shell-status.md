# sofiasip2shell — status

Admitted 2026-11-22 ~22:2xZ under standing approval #6 as the 90th engine
route. Frontier staged this lane at 22:26Z with a brief
(`reports/frontier-sofiasip2shell.md`), site charter, seed wall and an already
live two-pane window in the registry (96 windows), which was adopted and not
duplicated. Admission added the hy4-flash `max_parallel: 3` route and the path,
debounce and `10-slice.conf` units from the exact full-flag sync (pin
`0d686bbad55c849e88334da64efff9da88ad528a`; `written 3, removed 0`), followed
by `systemctl --user daemon-reload`; the path unit is enabled and active.
The wake unit was added to the site's owner resolver map so future failures
address `operator` rather than the dead `genome` fallback. Admission changes no
grade.

- Claim: GHSA-whfw-c3jj-99rp / CVE-2026-116791 (GitHub, 2026-10-28), HIGH 8.2,
  `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`, CWE-122/787. Affected `<= 1.13.17`,
  patched `>= 1.13.18`; tags `6198851a` and `ad36ac8f` are pinned with hashes
  in `lab/frontier/sofiasip2shell/harness/PROVENANCE.md`. The advisory claims
  an unauthenticated WebSocket upgrade as the only gate, up to 14 attacker-chosen
  XOR bytes past a 64 KiB chunk plus a one-byte NUL, and explicitly says RCE is
  not demonstrated.
- Primitive: `ws_read_frame()` iterates `wsh->datalen` (header plus payload)
  while indexing `wsh->body` (payload only). A masked frame with a 64-bit
  length overruns by 14 when the payload fills `bbuffer`; the terminating NUL
  adds one more byte. The fix bounds the loop by `wsh->rplen`, adds `+1` NUL
  slots in `ws_init()` and the body realloc, bounds the 64-bit length before
  narrowing and sizes the body from `blen + plen`.
- Evidence (`bash lab/frontier/sofiasip2shell/harness/run.sh`): two rounds over
  gcc 13.3 and clang 18.1 and both pins, with the function extracted verbatim
  from each pin. Operator replay from a copy of the harness outside the
  checkout: 128 PASS / 0 FAIL, rc 0; path-independent concatenated evidence
  hash `f6d088b793c8450b20bd26a49f309851502e6812e32f8e2891a4f04d25a3b3d3`,
  identical to frontier's clean `git archive 189441f` replay and byte-identical
  evidence files. Vulnerable pin under ASan: `heap-buffer-overflow`,
  `READ of size 1`, 0 bytes after a 64-byte region, frame `ws_read_frame` at
  `fns-1.13.17.inc:185`; fixed pin is clean with `DATALEN=78 RPLEN=64`. Plain
  build sentinel readback: NUL at offset 64, `0xEE ^ mask[i%4]` at 65..77 for
  mask `415a4243`, offset 78 untouched; fixed pin writes nothing.
- Grade: rung 1/2 and rung 3 (ASan-confirmed over-read in verbatim pinned code)
  plus scoped rung 4 (chosen XOR delta at chosen offsets in a controlled plain
  arena). Ceiling: no sofia-sip build, no real 64 KiB allocator layout, no
  WebSocket upgrade, listener or wire frame, no adjacent glibc chunk header or
  object corruption, no pointer control, marker, command or rung 5. "Chosen
  bytes" means chosen delta given bytes already present past the allocation.
- Cheapest next experiments: build pinned `v1.13.17` and `v1.13.18`, drive a
  real masked frame through `ws_read_frame()` with the actual `bbuffer`, then
  determine whether the overrun reaches a neighbouring object on a natural
  allocator layout; only then consider a loopback `ws-binding` listener with
  fixed-pin and short-frame controls. Rung 5 stays additive and per-build.
- Full stage: `reports/frontier-sofiasip2shell.md`. No witness verdict yet.
