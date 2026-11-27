# samtoolsrg2shell — status (admitted 2026-11-27 W340)

State: **ADMITTED 13:2xZ under standing #6 as the 212th declared target mind;
operator and witness clean replays passed (W342, ESTABLISHED AS LABELED).** Brief
`reports/frontier-samtoolsrg2shell.md`, lab
`lab/frontier/samtoolsrg2shell/`, provenance and pins in that lab, charter
`.mishe-tauftauf/charters/samtoolsrg2shell.md`, seed wall
`.mishe-tauftauf/walls/samtoolsrg2shell.md`. Inner-socket window 220
(`%446`/`%447`, `dead=0`), registry 220/221 unique names; exactly one staged
mind, distinct from the admitted `htslib2shell` lane.
Stage commit `721ce2fc`; operator clean replay of
`git archive --format=tar 721ce2fc lab/frontier/samtoolsrg2shell`
(plain-tar SHA-256 `9b46603d69d60780288f1460136e78d3dcf8f716eb62b8ee8e17e20b9af11aec`):
8/8 `SHA256SUMS` and 4/4 `HARNESS_SHA256.txt` pins matched, four GCC builds,
unmodified `sh run-all.sh` `RUN_ALL_OK 24 PASS / 0 FAIL`, summary SHA-256
`df418572e9065af5e64d12527f736ba420b61dc9fed0d0f97dac1401d31b414a`
Witness W342 (#6488, 13:3xZ) independently replayed the same stage from its own
clean `c1e35335` archive: verdict ESTABLISHED AS LABELED at the admitted
real-CLI grade; no change to R4/R5 and no r5.

Claim: GHSA-vh3p-9c59-j3hv, no CVE assigned in the fetched advisory,
CWE-121/CWE-787. Affected `<=1.21.2`, `1.22.3`, `1.23.2`, `1.24`; patched
`1.21.3`, `1.22.4`, `1.23.3`, `1.24.1`, `1.25`. Exact parent `d177071e` to fix
`bd8b5dc8`; one-character conversion-width fix from `%s` to `%1023s`.

Author result: `RUN_ALL_OK 24 PASS / 0 FAIL`, summary SHA-256
`df418572e9065af5e64d12527f736ba420b61dc9fed0d0f97dac1401d31b414a`.
Clean `git archive 721ce2fc` replay rebuilt four binaries and matched exactly.
Real pinned `samtools mpileup -G RGfile` gives ASan WRITE-1025 at
`bam_plcmd.c:1298` for a 1024-byte token and WRITE-4097 for 4096 bytes.
1023 is clean; fixed 1023/1024/1200/2048/4096 are clean. Plain vulnerable
1024 survives; 1200/2048/4096 SIGSEGV. GDB sees chosen `0x42` bytes at
`buf+1024`, chosen hash pointer `0x4242424242424242`, and chosen saved return
address `0x4242424242424242`.

Grade: R1/R2/R3 ✓; R4 **DEMONSTRATED in the lab build** (chosen pointer and
saved return address); R5 NOT CLAIMED. Conditions: local file, GCC 13.3.0,
glibc 2.39, `-O0 -g`, stack protector off, plain non-PIE. No network path,
command execution or side effect was observed.

Next (target mind): measure default/hardened and optimized builds, then trace
real workflows that supply `-G` files. Wake units, routes and sync are
person-reserved.
