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
  40-byte `old_rr` at `standin/display_ipopt.c:112`. `nm -n plain/harness`
  places `old_rrlen.1@0x4040`, `old_rr.0@0x4060` and `canary@0x40a0`, so
  the measured gap from `old_rr.0` is 64. Packet-derived bytes
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
  recorded in the operator wall. Witness W207 (#3822) returned ESTABLISHED
  AS LABELED at this pinned-function scope; no grade change, no r5.

## Wire stage (2026-11-24 20:3xZ, author-side)

- Real tree: `provision/hping-src` (HEAD `3547c769`, `display_ipopt.c`
  `e8ef2dd6…dcbb5e7b`) copied to `wire/hping-src`, configured `--no-tcl` and
  built with `-fsanitize=address -fcommon` plus an empty `compat/net/bpf.h`
  stub (BSD-only header, its use is `#if`-guarded off on Linux). No pinned
  source was hand-edited. The fixed tree is the same build with
  `pinned/fix.patch` applied (patched sha256
  `70f0112d12c52d8661736de85e1a5155ba717ca63b09b471cb7aaa7f0ba846c7`).
- Input: `hping3 -D -1 -G -I lo -c 3 -i 1 127.0.0.2` under `sudo -n`, PID
  captured from a wrapper shell; a second loopback socket sends an ICMP echo
  reply from 127.0.0.2 to 127.0.0.1 with IHL=15, RR option bytes
  `07 ff 48`, `OMIS` padding and a 64-byte `OMIS` payload. The echo id is
  packed in host byte order (x86 little-endian) to match hping's
  `getpid() & 0xffff` check.
- `cd lab/frontier/hping3shell/wire && sh run-wire.sh`: **9 PASS / 0 FAIL,
  rc 0**, reproduced from a clean copy of the lab. Pointer `0x48` aborts the
  live process with ASan `global-buffer-overflow`, `WRITE of size 68`, frame
  `display_ipopt wire/hping-src/display_ipopt.c:112`, 0 bytes after the
  40-byte `old_rr`; pointer `0x5a` gives `WRITE of size 86` at the same
  frame; the attack is deterministic on repeat. Valid RR (`rr_len=39`,
  pointer `8`) and the same attack against the patched real build both exit
  0 with no ASan error and print the RR from the injected packet.
- The kernel answers the malformed option with ICMP parameter-problem, but
  pcap still delivers the original packet to the live hping3 process. Raw
  output: `wire/evidence/wire-{attack,attack2,repeat,valid-rr,fixed-attack}.out`.
- Limits: ASan detection only in the real binary; chosen bytes at chosen
  offsets are still observed only in the plain stand-in harness. No pointer,
  IP or command control, no stock-glibc outcome, no r5. W207 witnessed only
  the earlier pinned-function stage; this wire stage awaits independent
  replay.

## Plain real build: chosen bytes at chosen offsets in an adjacent live global (W2, 20:5xZ, author-side)

`wire/plain-proof.sh` builds the same pinned tree **without** ASan
(`-O0 -g -fcommon`, `--no-tcl`), launches a real
`hping3 -D -1 -G -I lo -c 20 -i 1 127.0.0.2` under `sudo -n`, and injects
three loopback ICMP replies whose 40-byte RR option carries a unique,
non-periodic 36-byte marker (`0xa0…0xbb`) and whose ICMP payload carries a
unique 64-byte marker (`0x01…0x40`), with `rr_len=255`, `ptr=0xff` (so
`i = 251`). It then attaches GDB, computes the PIE base from
`/proc/$pid/maps`, dumps 120 bytes at `old_rr`, and `check_plain.py` verifies
the offsets. `wire/run-wire.sh` is unchanged.

- `nm -n -S plain-src/hping3` places `old_rr.0@0x29dc0` (40 bytes) and the
  adjacent real global `rc4_sbox@0x29e00` (256 bytes), i.e. `old_rr+0x40`.
  GDB independently labels the dumped line at `old_rr+64` as `<rc4_sbox>` in
  the live process.
- Attack: **4 PASS / 0 FAIL, rc 0**. `old_rr[46..109]` equals the unique
  payload bytes `0x01…0x40`; `rc4_sbox[0..45]` equals payload bytes
  18..63 (`0x13…0x40`) — attacker-chosen bytes at attacker-chosen offsets in
  a named adjacent global of the real plain build. Evidence:
  `wire/evidence/plain-attack-{gdb,proof}.out`.
- Baseline (`NO_INJECT=1`, no crafted frames): **3 PASS / 0 FAIL, rc 0**;
  `rc4_sbox[0..45]` is all zero. Evidence:
  `wire/evidence/plain-baseline-{gdb,proof}.out`.
- Preserved nuance: the shallow `old_rr[0..45]` are subsequently rewritten by
  kernel-generated parameter-problem RR replies (`i<=11`); the deeper chosen
  bytes persist because those later writes are shorter. The 251-byte copy
  reaches `rc4_sbox[0..185]`; only the first 46 bytes are asserted because
  those are the ones carrying our unique marker. No pointer, IP or command
  control, no r5; witness replay of this stage is UNKNOWN.
- Clean-copy replay: `git archive HEAD lab/frontier/hping3shell` extracted to
  `/tmp/w2-hping-clean` plus a copy of the gitignored `provision/` tree, then
  `sh plain-proof.sh` and `NO_INJECT=1 sh plain-proof.sh` from its `wire/`
  directory, gave 4 PASS and 3 PASS respectively, rc 0. The script rebuilt
  `plain-src/` from the provisioning tree; no pinned source was hand-edited.
- Patched-build control (`plain-fixed-proof.sh`, same crafted RR replies
  against the locally patched real tree, patched source sha256
  `70f0112d…b471cb7aaa7f0ba846c7`): **3 PASS / 0 FAIL**; `rc4_sbox[0..45]`
  stays all zero, so the chosen bytes are attributable to the unclamped
  `memcpy`. Evidence: `wire/evidence/plain-fixed-{gdb,proof,run}.out`.

## Current grade (2026-11-24 20:5xZ)

Rungs 1-3 on the verbatim pinned upstream function under ASan. Rung 4 is
WIRE-VISIBLE and now includes chosen bytes at chosen offsets in a named
adjacent global of the **real plain hping3 build**, author-side: a crafted
loopback RR reply reaches `display_ipopt()`; the ASan build aborts with
`WRITE of size 68` / `86` past `old_rr[40]`, and the plain build lets 251
attacker-chosen bytes land at chosen offsets in `rc4_sbox` (verified by GDB
with a zero baseline). A valid RR reply and the locally patched build stay
clean. No pointer/IP/command control and no rung 5. Stock glibc outcome,
`IPOPT_LSRR`, and any behavior change from the overwritten `rc4_sbox` stay
UNKNOWN. Both wire stages are author-side only; witness replay of each is
OWED.

## Witness verdict (W207, #3822)

Independent replay from clean `git archive 34c3c573`: 12 PASS / 0 FAIL, rc 0,
all source-patch and fix-patch hashes exact. The witness reproduced ASan
`WRITE-68`/`WRITE-86` at pinned `standin/display_ipopt.c:112`, with clean
fixed-source, safe and safe-zero controls, and confirmed the plain-build
chosen bytes using its own independent non-periodic marker and a locally
built fixed binary. ESTABLISHED AS LABELED at the pinned-function scope: no
grade change, no real hping build, libpcap/raw socket, wire, pointer/IP,
command or r5. Its only NIT was wording: `old_rrlen.1` is at `0x4040`,
`old_rr.0` at `0x4060`; the 64-byte canary gap is correct. The symbol labels
are corrected above and in the README row; no measurement changed.

## Next

Witness replay of both wire stages is owed: from a clean copy of
`lab/frontier/hping3shell`, run `cd wire && sh run-wire.sh` (9 PASS / 0 FAIL,
rc 0), `NO_INJECT=1 sh plain-proof.sh` (3 PASS), `sh plain-proof.sh` (4 PASS)
and `sh plain-fixed-proof.sh` (3 PASS, patched build). After those verdicts
the only depth lane is a measured attacker-controlled execution path; nothing
observed supports r5.
