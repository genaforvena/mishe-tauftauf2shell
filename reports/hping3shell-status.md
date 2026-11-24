# hping3shell — status

Admitted 2026-11-24 19:5xZ under standing approval #6 as the 134th engine
route. Claim: `CVE-2026-136131` (VulnCheck CNA 2026-11-24), CWE-787
out-of-bounds write, CVSS 4.0 6.0
`AV:N/AC:H/AT:P/PR:N/UI:P/VC:N/VI:L/VA:H/SC:N/SI:N/SA:N`. Affected hping
commits `7257579b` through master tip `3547c7691742c6eaa31f8402e0ccbb81387c1b99`;
no fixed version published. In the `IPOPT_RR` case of
`display_ipopt()`, the option pointer byte is clamped only to the packet's
option length, then reduced by `IPOPT_MINOFF`, and copied with `memcpy` into
`static char old_rr[40]`, so a reply declaring an RR length of up to 255 can
write up to 251 bytes past that global. Advisory reach through `hping3 -G`
and any RCE claim stay claims in this lab.

## Admission evidence

- Frontier brief `reports/frontier-hping3shell.md`; verbatim pinned source,
  fix patch and raw evidence in `lab/frontier/hping3shell/`
  (`PROVENANCE.md`, `pinned/`, `evidence/*.out`). `display_ipopt.c` sha256
  `e8ef2dd63b3f7b5e5d87d14a50bdc64c6befc94a8e21801f060708f2dcbb5e7b`,
  `waitpacket.c` sha256
  `f63e229c6d8708a23f29baeebb7e9d18dbefaa9a41db801c15866b07d52279e9`,
  `hping2.h` sha256
  `d3fa609e10355ca1ec2398b6ec9c670ff11574076795e86115ad0e4711699072`, fix
  patch sha256
  `23bb8db3b3d2ee241d355ce1af7c643ae1dc831ae6058c52fbdd2f806f400c92`,
  all recomputed by the harness on every replay.
- Operator verification 19:5xZ: `cd lab/frontier/hping3shell && sh run.sh`
  gave `PASS=12 FAIL=0`, rc 0. ASan reports `global-buffer-overflow` with
  `WRITE of size 68` (pointer `0x48`) and 86 (`0x5a`) 0 bytes after the
  40-byte `old_rr` at `standin/display_ipopt.c:112`. Plain build places
  `old_rr@0x4040` and the canary at `0x40a0` (gap 64); packet-derived bytes
  `4f 4d 49 53` ("OMIS") land at canary[0..3] for `0x48`, and "OMISHE-OO" ×2
  plus "OMIS" at canary[0..21] for `0x5a`, each matching the derived packet
  offset. Fixed-source attack, safe (`i=4`), safe-zero (`i=0`) and plain-safe
  controls are clean. Frontier's clean `git archive 7ec6a3bd` replay is
  recorded in commit `34c3c573`.
- Frontier's live two-pane window 142 (`hping3shell`) was adopted without
  duplication (registry entries present, seed wall in place). Charter
  written; hy4-flash route 133→134, both resolver keys 267→269, wake-failure
  signal registration via the exact full-flag sync at pin
  `0d686bbad55c849e88334da64efff9da88ad528a`; pinned full-flag doctor as
  recorded in the operator wall. Witness replay is UNKNOWN.

## Current grade

Rungs 1-3 on the verbatim pinned upstream function under ASan; rung 4
PARTIAL — packet-derived chosen bytes at chosen offsets in a live adjacent
global in the plain build. No hping build, no libpcap or raw socket, no live
process, no wire input, no pointer/IP/command control and no rung 5. The
advisory's `AV:N` is prose; stock glibc outcome, post-fix real `.bss` layout
and the `IPOPT_LSRR` branch are UNKNOWN. This is author-side evidence, not an
independent verdict.

## Next

Request an independent witness replay. The cheapest next experiment is a
loopback ASan + libpcap build of the pinned tree running `hping3 -G` with an
injected crafted RR reply from a second loopback socket, compared against a
locally patched build and a valid-RR control. A wire-visible rung 4 requires
that packet to reach `display_ipopt()`; rung 5 additionally requires a
measured attacker-controlled execution path and is not claimed here.
