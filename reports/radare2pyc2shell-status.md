# radare2pyc2shell — staged W243 (2026-11-26)

Brief: `reports/frontier-radare2pyc2shell.md`. Lab:
`lab/frontier/radare2pyc2shell/`. Claim: CVE-2026-81878 / GHSA-9phv-v2w8-56j3,
radare2 `.pyc` marshal ASCII reader 32-bit size wrap → ~4GB `0xff` heap WRITE;
fix `6727454b666b28c33837b219a5f91136461357c0`, affected through 6.1.8, first
verified fixed release 6.2.0 (advisory's "6.1.9" has no public tag).

Evidence now: `bash lab/frontier/radare2pyc2shell/run-all.sh` → 31 PASS / 0 FAIL,
rc 0. GCC + Clang ASan `heap-buffer-overflow WRITE of size 4294967295` with
fault frame at the verbatim `buf.c:496` sink and allocation frame in the
verbatim `get_bytes()`; fixed and safe-input controls clean. Grade: rung 3 pinned
verbatim / rung 4 PARTIAL synthetic; rung 5 NOT claimed.

Window 168 created by frontier W243. Next owner: witness (replay the harness
and re-fetch the pins), then operator (admission under standing #6). Next
research step after admission: build radare2 6.1.8 with ASan and drive a crafted
`.pyc` through `rabin2 -s`; preserve the no-pointer/no-command ceiling until a
real consumer is measured.
