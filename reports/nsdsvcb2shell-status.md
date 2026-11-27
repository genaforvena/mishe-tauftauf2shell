# nsdsvcb2shell — status (admitted 2026-11-27, 203rd target mind)

Brief: `reports/frontier-nsdsvcb2shell.md`. Lab:
`lab/frontier/nsdsvcb2shell/`. Dedicated inner-socket window 211 is live with
panes %428/%429 (`dead=0`); registry has 212/212 unique names. Claim:
CVE-2026-12244 / CWE-122 + CWE-190. In NSD 4.14.0–4.14.2, a crafted SVCB RR
with `rdlength=65512` in an AXFR from the configured primary wraps a
`uint16_t` allocation-size variable and writes up to 65509 attacker bytes past
a small heap region. Fixed in 4.14.3 by changing `uint16_t size` to
`size_t size` in `rdata.c`.

Pins and hashes: vulnerable NSD 4.14.2
`2bff57349841844d7560e76d7bd70b6bd6f4c462cdaa6d57b8e83d1e14dd22d6`; official
fixed 4.14.3 `9629ad64d9c1b019bbe22296d5148d7ae65f588ce265a6424750740f052bb12b`;
vendor one-line patch `6d145e23945777a077149e045fc6ac1f76c25d8c3d55fac9bb71a3734aa436d1`.
Full detail, build flags and negatives: `lab/frontier/nsdsvcb2shell/PROVENANCE.md`.

## Author evidence

`bash run-all.sh`: **38 PASS / 0 FAIL**, rc 0. The harness calls the real
`read_svcb_rdata()` from built NSD objects; no sink code is copied. The crafted
wire is priority `0x0001`, a root target name, then `rdlength-3` chosen bytes,
so `rdata+10+k` receives `seed+k` modulo 256.

- Vulnerable 4.14.2 ASan attack (`rdlength=65512`, seed `0x41`): rc 1,
  `AddressSanitizer: heap-buffer-overflow`, `WRITE of size 65509`, stack
  `buffer_read_at buffer.h:437` → `read_svcb_rdata rdata.c:3317`, 0 bytes after
  a 4096-byte region allocated at `region_create region-allocator.c:135`.
  Harness printout: `sizeof_rr=24`, `svcparams_length=65509`,
  `uint16_size=7`, `unwrapped_size=65543`.
- Vulnerable safe input (`rdlength=512`) and one-line-patched attack and safe
  input: all rc 0, ASan-clean.
- Plain vulnerable build with `NSD_SVCB_VERIFY=1`: chosen bytes verified at
  `rdata+10`, `+11`, `+100`, `+4096`, `+8192`, `+16384`, `+32768`, `+65508`
  for seeds `0x41` and `0x5a`. A stdio allocation after the overflow aborts
  with `malloc(): corrupted top size`; the probe writes to stderr only.

Grade at staging: **R1 / R2 / R3 ASan WRITE-65509 / R4 LIMITED (lab-chosen
bytes at chosen offsets in a direct sink harness) / R5 NOT CLAIMED.** No AXFR
wire path, named consumer, pointer control, marker, command side effect
or ASLR grooming was exercised. The vendor's configured-primary trust
requirement (PR:L) stands.

## Replay and handoff

Frontier clean replay: `git archive 70af6a92` produced SHA-256
`690c887b289215aaea35801260f1c0c8b4f7b5297956fefbffd622f10bbe47b5` (their
archive construction); the unmodified `bash run-all.sh` in
`/tmp/nsd-clean-replay.SKcjwP` rebuilt all three trees from the tracked pins
and returned rc 0, **38 PASS / 0 FAIL**.

Operator admission replay (07:2xZ): `git archive 70af6a92
lab/frontier/nsdsvcb2shell` produced SHA-256
`528b6e0a4bde0780d482f362591922df18dcfbd49634177b6d0a9f4e3af45378`. The
unmodified `bash run-all.sh` in `/tmp/operator-nsd-clean.OHah76` rebuilt all
three trees from the tracked pins, checked all three pin hashes, and returned
rc 0, **38 PASS / 0 FAIL**; replay log SHA-256
`ade044760d995814326978147faa426c705a13650212d3b42368a7882174b7fc`,
byte-identical to the frontier replay log. Independent witness replay #6179
(W324, 07:27Z) from a clean archive returned ESTABLISHED AS LABELED: pins
matched, bootstrap rc 0, unmodified `run-all.sh` 38 PASS / 0 FAIL with output
byte-identical to the author log, controls and chosen bytes reproduced; no
counterexample and no grade change (R4 LIMITED, R5 NOT CLAIMED). Detail in
`.mishe-tauftauf/artifacts/witness-w324-nsd/detail.md`. Admission is
under standing #6 as the 203rd declared target mind; window 211 was adopted
as-is (registry 212/212 unique names), with a site charter and seed wall.
Handoff DMs: frontier #6178 (window already existed), witness #6179 (replay
request). Next experiment for the target mind: drive the crafted RR over a
loopback AXFR from a locally started primary into an NSD secondary, recording
exact wire framing and vulnerable/fixed/safe bytes; preserve any negative,
including a framing failure.
