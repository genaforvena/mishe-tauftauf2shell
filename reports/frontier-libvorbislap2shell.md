# Frontier brief — libvorbislap2shell (CVE-2026-137079)

Status 2026-11-27 W376: **SCREENED at pinned-sink scope**, not staged as a
target mind and not admitted. R3 CONFIRMED by ASan on the verbatim pinned
`_ov_getlap()` tail; R4 **NOT CLAIMED** (no chosen-byte write was measured);
R5 **NOT CLAIMED**. No window was created: the candidate lacks a local real
file/wire trigger and has no released fixed version. Harness
`lab/frontier/libvorbislap2shell`, `sh harness/run-all.sh` gives
`RUN_ALL_OK 16 PASS / 0 FAIL`.

## Verified ground truth (claim, not assumed)

- CVE-2026-137079, CNA MITRE, published 2026-11-25. Claim: libvorbis through
  1.3.7 has a stack buffer overflow in `_ov_getlap()` (`lib/vorbisfile.c`):
  `vorbis_synthesis_lapout()` can return a negative sample count that is
  passed as a `size_t` length to `memcpy()`. A short valid Ogg Vorbis file
  with suitable block sizes and two consecutive lapped seeks is claimed to
  overwrite stack frames in a decoder application.
  https://cveawg.mitre.org/api/cve/CVE-2026-137079
- Upstream points to v1.3.7 `vorbisfile.c:2242` and `block.c:1034`, plus PRs
  #136 and #139. Both PRs were **open and unmerged** on 2026-11-27, so the
  fixed side is a proposed patch, not a release. Claims about a real Ogg
  trigger and code execution remain claims; no external target was probed.
- Pins: v1.3.7 tarball `270c7693…3afd13`, PR #136 diff `39041eac…e55744e`,
  PR #139 diff `414622fd…f9bcb1`; full hashes and URLs in
  `lab/frontier/libvorbislap2shell/PROVENANCE.md`.

## Source-bound mechanism

The pinned v1.3.7 tail at `lib/vorbisfile.c:2238-2253` first tries normal
decode, then, when `lapcount < lapsize`, calls
`vorbis_synthesis_lapout(&vf->vd, &pcm)` into `int samples`. The guard is
`if (samples == 0)`; any negative value falls into the `else` path. The
clamp `if (samples > lapsize - lapcount) samples = lapsize - lapcount;`
does not bound negative values. The sink at `:2250` is

```c
memcpy(lappcm[i] + lapcount, pcm[i], sizeof(**pcm) * samples);
```

`sizeof(**pcm)` is `size_t`, so a negative `samples` becomes a near-`SIZE_MAX`
length. The pinned zero-sample branch at `:2245` also computes
`sizeof(**pcm) * lapsize - lapcount` instead of
`sizeof(**pcm) * (lapsize - lapcount)`, overrunning the `alloca` destination
by `(sizeof(**pcm) - 1) * lapcount` bytes even when `samples == 0`. PR #136
fixes both expressions; PR #139 changes `block.c` so the negative sample
count is not produced in the first place. Only PR #136 is used as the local
fixed control, because the harness stand-in supplies the sample count.

## Local experiment

`harness/gen.sh` extracts the pinned tail verbatim from the tarball under
`#line` directives; only surrounding types and
`vorbis_synthesis_lapout()` are stand-ins. `run-all.sh` verifies three
SHA-256 pins, builds vulnerable and PR136-patched arms under GCC 13.3.0 at
`-O0 -g` (ASan and `-fno-stack-protector`), and runs sample counts `-4` and
`0` with `lapsize=64`, `lapcount=8`, a 64-float `alloca` destination filled
with chosen `0x43` bytes, and a separate source buffer. No Ogg file, decoder
application, listener or network traffic is involved.

Observed:

- Vulnerable ASan, `samples=-4`: `AddressSanitizer: negative-size-param
  (size=-16)`, frame `main build/vuln/lib/vorbisfile.c:2250` (the pinned
  `memcpy`), rc 1. This is ASan's refusal to perform an impossible-size
  copy, **not** a chosen-byte write.
- Vulnerable ASan, `samples=0`: `dynamic-stack-buffer-overflow`, `WRITE of
  size 248` at `vorbisfile.c:2245` (the pinned `memset`), rc 1. The
  destination has 224 bytes free from `lapcount`; the extra 24 bytes are
  zero, not attacker-chosen.
- Vulnerable plain `-fno-stack-protector`, `samples=-4`: runs to completion
  with `RETURN lapcount=4`; no crash and no byte capture was taken, so the
  effect of the huge-length `memcpy` on this host is UNKNOWN, not a pass.
- PR #136-patched ASan and plain arms are clean on both counts (`RETURN
  lapcount=64`). Vulnerable plain with `samples=0` completes; its zero
  overwrite was not measured.
- `RUN_ALL_OK 16 PASS / 0 FAIL`; raw logs are path- and PID-specific and
  gitignored, assertions are stable.

## Rung assessment and feasibility

- R1: deterministic trigger at the pinned sink via a stand-in return value;
  a real-file trigger is UNKNOWN here.
- R2: the two arithmetic defects are source-visible; attacker-chosen bytes
  in the real call would come from `pcm[i]`, not from this harness's buffer.
- R3: ASan-confirmed corruption on both pinned expressions, in the
  vulnerable arm only.
- R4 **NOT CLAIMED**: ASan sees an impossible-size parameter and a zero-byte
  overwrite; neither yields chosen bytes at a chosen offset. The plain
  negative-count run completes, so there is no observed crash or pointer
  control either. A witness would need a measured store to upgrade this.
- R5 **NOT CLAIMED**: no live decoder, wire/request input, command or side
  effect; the vendor advisory's application-level claim is untested.

Tractability: the arithmetic is small and the pinned function extracts
cleanly, but the missing real-file trigger, the unmerged fixed side and the
absence of a measured chosen-byte store make this a lower-priority candidate
than a released-fix target. It is screened, not admitted.

## Cheapest next experiment

Build the pinned 1.3.7 library with ASan, craft the short two-block Ogg file
described in the advisory, and drive `ov_seek()`/lapped decode twice through
an unmodified decoder CLI. Record whether
`vorbis_synthesis_lapout()` actually returns a negative count, the exact
`pcm[i]` source bytes, and whether ASan reports a real stack overflow at
`:2250` or only `negative-size-param`. Test PR #139 as the root-cause control
alongside PR #136. Only a measured chosen-byte store in a real consumer
would justify staging this as a target mind.

## Duplicate screening

Checked against `reports/frontier-*.md`, target charters/walls and the
frontier wall's do-not-duplicate list before provisioning: `stbvorbis2shell`
owns stb_vorbis (single-header, separate sink) and `live555vorbis2shell`
owns Live555's Vorbis path; neither is Xiph libvorbis `vorbisfile.c`.
`assimp2shell`, `librecad2shell`, `pgactive2shell`, GIMP, FFmpeg, SOES and
FontForge already own their respective advisory batches.
