# Frontier brief — hping3shell (CVE-2026-136131)

Status at staging (2026-11-24 19:4xZ): STAGED at rung 3 / rung 4 PARTIAL,
witness replay PENDING, operator admission PENDING. Superseded after
admission by a target-owned status report, if one is written.

## Verified ground truth (read-only provisioning)

- CVE-2026-136131, VulnCheck CNA, published and updated 2026-11-24;
  CWE-787 out-of-bounds write; CVSS 4.0 6.0
  `AV:N/AC:H/AT:P/PR:N/UI:P/VC:N/VI:L/VA:H/SC:N/SI:N/SA:N`, CVSS 3.1 5.9
  `AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:H`. Affected hping commits
  `7257579bc9e722d3f1e28d42c0cd93d769260b2b` through
  `3547c7691742c6eaa31f8402e0ccbb81387c1b99` (master tip); no fixed version
  published. Finder Umut SEVİNÇ (VulnSVNC). Sources:
  https://www.cve.org/CVERecord?id=CVE-2026-136131 ,
  https://www.vulncheck.com/advisories/hping3-through-commit-3547c76-out-of-bounds-write-in-display-ipopt-via-record-route ,
  https://github.com/antirez/hping/issues/80 .
- Advisory claim: a probed host, on-path attacker or spoofer sends replies
  with RR option lengths up to 255 to hping3 running `-G`/`--rroute`;
  `display_ipopt()` overflows the static 40-byte `old_rr` buffer, corrupting
  global memory and crashing hping3. Trigger path `wait_packet()` →
  `display_ipopt()` (`pinned/waitpacket.c`); no upstream fix at master tip.
- Checked `reports/frontier-*.md`, the lab tree and the frontier wall's
  do-not-duplicate list before provisioning: no prior hping entry. FFmpeg
  batch, NGINX/Node and all admitted targets remain untouched.

## Source-bound mechanism (pinned bytes, no hand-edited source)

`lab/frontier/hping3shell/pinned/display_ipopt.c` is byte-identical to
upstream master commit `3547c769`, sha256
`e8ef2dd63b3f7b5e5d87d14a50bdc64c6befc94a8e21801f060708f2dcbb5e7b`;
`pinned/waitpacket.c` sha256
`f63e229c6d8708a23f29baeebb7e9d18dbefaa9a41db801c15866b07d52279e9`;
`pinned/hping2.h` sha256
`d3fa609e10355ca1ec2398b6ec9c670ff11574076795e86115ad0e4711699072`.

In the `IPOPT_RR` case (pinned lines 93-113): `j = *++cp` (option length),
`i = *++cp` (option pointer), `i` is clamped only to `j` (both packet bytes),
then `i -= IPOPT_MINOFF` (4). After the `i <= 0` skip, `memcpy(old_rr, cp, i)`
copies up to `255 - 4 = 251` bytes into `static char old_rr[MAX_IPOPTLEN]`
(40 bytes, `.bss`). Neither the buffer capacity nor the remaining header
length (`hlen`) is checked. The issue's suggested local fix clamps `i` to
`MAX_IPOPTLEN` and `hlen` before the copy; `pinned/fix.patch` (sha256
`23bb8db3b3d2ee241d355ce1af7c643ae1dc831ae6058c52fbdd2f806f400c92`)
applies that hunk to the verbatim source without editing the vulnerable pin.

## Lab evidence (`lab/frontier/hping3shell/`)

`sh run.sh` rechecks the pin hashes, applies the fix patch, builds ASan and
plain binaries from verbatim copies under `standin/`, and runs 12 checks:
**12 PASS / 0 FAIL**, rc 0 in-tree and from a clean `git archive 7ec6a3bd
lab/frontier/hping3shell | tar x -C /tmp/w212-hping` replay. Raw output in
`evidence/*.out`.

- `asan/harness attack`: crafted RR length 255, pointer `0x48` → `i = 68`;
  ASan `global-buffer-overflow`, `WRITE of size 68`, frame
  `display_ipopt standin/display_ipopt.c:112`, 0 bytes after the 40-byte
  `old_rr` global, rc 1 (`evidence/asan-attack.out`).
- `asan/harness attack2`: pointer `0x5a` → `i = 86`, `WRITE of size 86`,
  same frame, rc 1 (`evidence/asan-attack2.out`).
- Plain build: `nm -n` measures `old_rr` at `0x4040`, adjacent canary at
  `0x40a0`, gap 64. The overflow writes packet-derived bytes into the live
  canary at chosen offsets: pointer `0x48` leaves `4f 4d 49 53` ("OMIS") at
  canary[0..3]; pointer `0x5a` leaves `4f 4d 49 53 48 45 2d 4f 4f` repeated
  ("OMISHE-OO" ×2 plus "OMIS") at canary[0..21]. Each observed value matches
  the packet byte at `22 + 64 + offset` derived from the pinned copy.
- Controls: `safe` (`i=4`, in-bounds) and `safe-zero` (`i=0`, skipped) rc 0
  with no ASan error; fixed-source attack with the same crafted packet rc 0
  with no ASan error; plain safe leaves the canary all zero.

## Rung-4 feasibility and ceiling

Rung 3 is confirmed on the verbatim upstream function under ASan. Rung 4 is
PARTIAL: packet-derived chosen bytes land at chosen offsets in a live
adjacent global in the plain build. There is no hping build, no pcap/raw
socket, no live process, no wire input, no pointer/IP/command control and no
rung 5. The advisory's AV:N reach is a claim, not exercised here; the
post-fix real-binary `.bss` layout and stock glibc outcome stay UNKNOWN.
ASan redzones put the adjacent bytes in poison, so the canary observation is
necessarily from the plain build. The `IPOPT_LSRR` branch's unbounded forward
walk is noted in issue #80 but not tested here.

## Cheapest next experiment

Build the pinned hping tree under ASan with libpcap, run
`hping3 -G` against a loopback target and inject a crafted RR reply from a
second loopback socket; compare with a locally patched build and a valid RR
control. If the loopback packet reaches `display_ipopt()`, that moves the
claim to a wire-visible rung 4. Operator admission and witness replay are
owed; do not duplicate this target.
