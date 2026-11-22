# ytnef2shell — status

Admitted 2026-11-22 ~22:4xZ under standing approval #6 as the 91st engine
route. Frontier staged this lane at 22:42Z with a brief
(`reports/frontier-ytnef2shell.md`), site charter, seed wall and an already
live two-pane inner tmux window (index 96, registry entry 97), which was
adopted and not duplicated. Admission added the hy4-flash `max_parallel: 3`
route and the path, debounce and `@ytnef2shell` slice drop-in from the exact
full-flag sync (pin `0d686bbad55c849e88334da64efff9da88ad528a`; `written 3,
removed 0`), followed by `systemctl --user daemon-reload`; the path unit is
enabled and active. The wake unit was added to the site's owner resolver map
so future failures address `operator` instead of the dead `genome` fallback.
Admission changes no grade.

- Claim: GHSA-jhg4-xcxm-cfg6 (maintainer Yeraze, published 2026-11-20, HIGH,
  CWE-190/122/125, no CVE at publication). Affected `<= 2.1.2`, patched
  `2.1.3`; pins `d9f08914` / `f0ccad7d` and the fix diff are committed and
  hashed in `lab/frontier/ytnef2shell/harness/PROVENANCE.md` and
  `harness/evidence/pin-hashes.txt`. The advisory claims mail-client and
  procmail reachability and DoS, not RCE; those reachability claims were read,
  not exercised here.
- Primitive: inside `DecompressRTF()` the guard
  `comp_Prebuf.size >= INT_MAX - uncompressedSize` is evaluated in unsigned
  32-bit arithmetic and passes for a stream size near `0xFFFFFFFF`;
  `calloc(207 + uncompressedSize, 1)` then wraps to 0..206 bytes while the
  following `memcpy` writes the fixed 207-byte `RTF_PREBUF` anyway, giving a
  1..207-byte overrun with chosen length and fixed content. The MELA branch
  separately copies `uncompressedSize` bytes from `src + 4` without checking
  the property size. The fixed pin reverses the guard operands, bounds the
  MELA read and sets `*size`.
- Evidence (`bash lab/frontier/ytnef2shell/harness/run.sh`): the pinned
  `RTF_PREBUF`, `SwapDWord()` and `DecompressRTF()` are re-extracted and checked
  verbatim on every run; two rounds over gcc and clang, both pins, ASan and
  plain-arena cases. Operator replay from a fresh `/tmp` copy of the staged
  lane: rc 0, 240 PASS / 0 FAIL, path-independent concatenated content hash
  `a2819d82cc5fdf23c88ee65fc4d8eb08a48fe01be80afa092fdf37ac43bce639` over 72
  normalized logs, identical to frontier's clean `git archive 3f72935` replay.
  Vulnerable pin ASan: `heap-buffer-overflow`, `WRITE of size 207`, 0 bytes
  after a 16-byte region, frame `DecompressRTF`; 1-byte and 206-byte region
  variants for the other chosen sizes; MELA `READ of size 64` past a 20-byte
  input. Plain arena: `ALLOC=16 OVERRUN=191 B0=64 BMID=6f BEND=78 TAIL=ee`
  plus 0/206-byte variants; fixed pin `ALLOC=none OVERRUN=0 TAIL=ee` with
  `Corrupted file` on all four attack inputs; a well-formed 8-literal stream is
  clean on both pins.
- Grade: rung 1/2 and rung 3 (ASan-confirmed write in verbatim pinned code)
  plus scoped rung 4: the attacker chooses the wrapped allocation size and
  therefore the destination offsets of fixed prebuffer bytes. Ceiling: no
  ytnef build, TNEF blob or property parser, no mail client or procmail hook,
  no natural allocator layout, no adjacent object corruption, no pointer
  control, marker, command or rung 5. "Chosen" means chosen length and offsets,
  not chosen content.
- Next experiments: build pinned `v2.1.2` and `v2.1.3` with ASan, feed a real
  `winmail.dat` whose `PR_RTF_COMPRESSED` property declares
  `compressedSize = property_size - 4` and `uncompressedSize = 0xFFFFFF41`,
  and run `ytnefprint` / `ytnef +F` on a local file. Only then test whether the
  overrun reaches a neighbouring object on a natural layout; fixed pin and
  well-formed property remain mandatory controls. Rung 5 stays additive and
  per-build.
- Full stage: `reports/frontier-ytnef2shell.md`. No witness verdict yet.

## W1 update — 2026-11-22T22:57Z

Pinned `v2.1.2` and `v2.1.3` were built with ASan and driven through the
advisory's named `ytnefprint` -> `MAPIPrint()` caller on real upstream TNEF
files with a four-byte `uncompressedSize` patch plus repaired TNEF checksum
(`lab/ytnef2shell/make_inputs.py`, `run_real.sh`, `PROVENANCE.md`).
Vulnerable pin: ASan `WRITE of size 207`, 0 bytes after a 16-byte region, frame
chain `DecompressRTF ytnef.c:1573` -> `MAPIPrint :1454` -> `PrintTNEF main.c:172`
-> `main :87`, allocation at `:1571`; same for 0/206-byte variants and all
winmail.dat-derived inputs. Fixed pin: rc 0, no ASan, `Corrupted file`;
unmodified files clean on both pins.

In the non-ASan v2.1.2 build, gdb before/after dumps at `:1573`/`:1574` show the
following glibc chunk's size field changing from `0x7d1` to the invalid
`0x7b30323762617466` ("ftab720{") while the current 0x21-byte header is intact;
execution then aborts with `malloc(): invalid size (unsorted)` (rc 134) in
`_int_malloc`. That is allocator-metadata corruption on a natural layout, not
the frontier harness's static arena.

Grade now: rungs 1–3 in a real parse; rung 4 extended to adjacent glibc chunk
header corruption with chosen length/fixed content. Ceiling unchanged for rung
5: no pointer control, marker, command, mail delivery, procmail hook or
control-flow hijack; advisory DoS claim is consistent with observation. Full
evidence and honest limits in `reports/ytnef2shell-w1.md`. No witness verdict
yet.
