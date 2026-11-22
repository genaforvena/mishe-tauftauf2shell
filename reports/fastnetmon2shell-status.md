# fastnetmon2shell — status

Admitted 2026-11-22 ~17:2xZ under standing approval #6 as one of three
frontier-staged target minds (engine routes 77–79, inner windows 82–84).
Charter `.mishe-tauftauf/charters/fastnetmon2shell.md`, seed wall
`.mishe-tauftauf/walls/fastnetmon2shell.md`. Frontier staged the find in
commit `f2dad5e`-era work; brief `reports/frontier-fastnetmon2shell.md`. The
window already existed (two-pane, top tail of the brief, bottom
`plant_view --output --log --follow`); admission added the model route, the
wake-failure signal and the six units, not a duplicate window.

- Claim: CVE-2026-48689 (Debian tracker; research blog
  `lorikeetsecurity.com/blog/fastnetmon-cve-2026-48689-dynamic-buffer-off-by-one`;
  upstream fix PR 1051). Off-by-one heap overflow in five methods of the
  header-only `dynamic_binary_buffer_t`: the bounds check used
  `offset + length > max_size + 1`, so a one-byte append at
  `used_size == max_size` writes one past the allocation. Affected through
  1.2.9 per the blog; fixed upstream 2.0.380 / Debian backport
  1.2.9-0+deb13u1. Pre-auth NetFlow/sFlow/IPFIX/BGP reach and the
  heap-metadata-to-PC transition are blog claims, not measurements here.
- Brief: [reports/frontier-fastnetmon2shell.md](frontier-fastnetmon2shell.md).
  Pins `lab/frontier/fastnetmon2shell/pins/PINS.txt`: vulnerable parent
  `97b04568b6f12977aedb9682fcd9ca7ca952e84a`, fixed commit
  `fa80390ed446f887ca6fa39c9e5b6fff8846e822`. The harness compiles the real
  pinned header, not a reimplementation.
- Primitive: with a 24-byte allocation filled to `used_size == 24`,
  `append_data_as_pointer()` at `src/dynamic_binary_buffer.hpp:115` accepts a
  25th byte and `memcpy(base+24, src, 1)` writes index 24 — the low byte of the
  next chunk's size on this glibc. The fixed pin removes the `+ 1` and rejects.
- Grade at admission: **rung 3 ASan-confirmed and rung 4 chosen-byte at chosen
  offset on the real pinned header, at direct-call harness scope.** Vulnerable
  ASan gives `WRITE of size 1`, `0 bytes after 24-byte region`; fixed ASan clean;
  plain vulnerable readback shows `byte[24]=0x41`/`0x5a`, plain fixed rejected.
  `bash harness/run.sh` replays from a clean checkout with normalized logs and
  hashes in `evidence/`/`EVIDENCE_HASHES.txt`.
- UNKNOWN: no daemon was built and no packet was sent. Wire reach to
  `used_size == max_size`, the NetFlow/BGP parser frame chain, pointer control,
  marker execution and any command side effect are unmeasured. Rung 5 UNKNOWN.
- Next experiment: build the pinned vulnerable daemon and drive the smallest
  real NetFlow v9 template that fills a buffer to its maximum, then supplies
  one extra byte, under ASan; the decisive observation is a WRITE-1 whose frame
  chain includes both a wire parser and the pinned header line, with 2.0.380
  rejecting the same input.
- Witness replay is owed. No rung 5 claim.
