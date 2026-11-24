# contiki2shell lab provenance

- Advisory: VulnCheck 2026-11-23, CVE-2026-135292,
  <https://www.vulncheck.com/advisories/contiki-ng-through-5.2-out-of-bounds-write-via-mpl-seed-id-length>.
- Upstream fix: PR #3312 (open 2026-11-23),
  <https://github.com/contiki-ng/contiki-ng/pull/3312>.
- Pinned source: Contiki-NG `release/v5.2`, annotated tag SHA
  `a0eb46fe21dc6513f1e34fd28b05090cb95918e3`, peeled commit
  `4ccd1a3b9e767f168d12ec3df187fe6b7dc736b5`.
- Tarball: `contiki-ng-release-v5.2.tar.gz`, SHA-256
  `78133c774812197b43a979e4b8f1026c8740929c45f749c2dccd4a2670819c95`,
  fetched 2026-11-24 from
  `https://github.com/contiki-ng/contiki-ng/archive/refs/tags/release/v5.2.tar.gz`.
  The extracted tree `contiki-ng-release-v5.2/` is gitignored bulk.
- Lab-only edits inside the ignored pinned tree:
  `examples/multicast/harness.c` (new injection harness),
  `examples/multicast/project-conf.h` (`MPL_CONF_PROACTIVE_FORWARDING 1`),
  temporary `fprintf` diagnosis in `os/net/ipv6/multicast/mpl.c` and
  `os/net/ipv6/uip6.c`. The last two are removed for the final replay.
- Builds: real native target, `CONTIKI_PROJECT=harness`,
  `CC='gcc -fsanitize=address -g -O0'`, `LD='gcc -fsanitize=address'` for
  ASan runs; `BUILD_DIR_BOARD=build/gdb` with plain `gcc` for gdb.
- No external probes. The native platform could not open `/dev/net/tun` and
  ran without network; all packets were injected into `uip_process()` in
  this process. Wire delivery is UNKNOWN, not claimed.
