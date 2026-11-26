# Frontier brief: live555vorbis2shell — CVE-2026-137587 (unchecked memmove reads in parseVorbisOrTheoraConfigStr)

**Status: STAGED 2026-11-26 W296 — rung 3 ASan-confirmed heap-buffer-overflow
READ of size 65535/65534/98 at three verbatim pinned sink lines; rung 1 and
rung 2 NOT CLAIMED (plain build exits 0); rung 4 and rung 5 NOT CLAIMED.**
Everything in the claim section is attributed to the cited public pages; the
pinned bytes and observations below are this plant's own. The witness re-runs
any published claim. Operator owns admission under standing #6; frontier owns
no further work after handoff.

## Verified ground truth (claim sources read 2026-11-26)

- **Claim sources:** CVE record
  `https://www.cve.org/CVERecord?id=CVE-2026-137587`, canonical JSON
  `https://cveawg.mitre.org/api/cve/CVE-2026-137587` (CNA VulnCheck, published
  2026-11-26, CNA datePublic 2026-08-25), CNA advisory
  `https://www.vulncheck.com/advisories/live555-before-2026.08.25-heap-out-of-bounds-read-via-parsevorbisortheoraconfigstr`,
  NVD API record, and `https://github.com/advisories/GHSA-h6r7-83p9-fpf5`
  (unreviewed GitHub import, no package/version data). Upstream's only note is
  the `2026.08.25` changelog entry
  (`https://download.live555.com/changelog.txt`): "Fixed a bug in
  VorbisAudioRTPSource that could have caused a malicious SDP description to
  crash a RTP client. (Thanks to 'Tristan' ...)".
- **Versions:** affected `< 2026.08.25` (custom range, CPE
  `versionEndExcluding 2026.08.25`); fixed 2026.08.25. Upstream publishes
  dated tarballs, not git tags. The fix is pinned here to two mirror commits
  with byte-identical Vorbis blobs (below); no upstream tagged release exists.
- **Claimed primitive:** CVSS 7.1 (both v4.0 and v3.1), CWE-125. The advisory
  says `parseVorbisOrTheoraConfigStr()` trusts attacker-supplied 16-bit header
  length fields, giving a heap out-of-bounds read; a malicious RTSP server or
  crafted SDP Vorbis/Theora config can crash a client or leak heap memory via
  proxied SDP. **None of the primary advisory pages names `memmove`,
  `VorbisAudioRTPSource.cpp`, line numbers, `a=fmtp`, `config=` or base64.**
  Those details come from the fix diff and raw source, not the advisories.
- **Fix (verified raw patches and blobs):** `ef760df8569703b93f8df990a07086d7e760d171`
  in `live555-mirror/live555-mirror` (parent `82ca996f9960c8ab69bf98570b116da107ca89f0`)
  and `03015a0ae5ab3a1c53106eb938213d0d05e16f1e` in
  `lengfeld/live555-unofficial-git-archive` (parent
  `a00042c861529485ff9c2c572749865805334c23`) carry the same Vorbis file
  change: git blob `edce800dbd54842c6149c4277782d3f20d7c25d6` (6665 bytes) →
  `fd3bbe4e842884fad3b2011e4f8a06974d50b8f3` (6776 bytes). The fix adds three
  `if (rem < …HeaderSize) break;` guards before the copies and unnests them.
  The two commits differ in other files (the second also touches
  `H264or5VideoRTPSink.cpp` and a config revision); only the Vorbis file is
  used here.

## Source-bound mechanism (pinned bytes)

`pins/VorbisAudioRTPSource.cpp.vuln` is the verbatim pre-fix mirror blob
(SHA-256 `bf1e426a3761642089a8dafff635cd24b0b4fc609e779202832d1cb4f5c11ddf`);
`pins/VorbisAudioRTPSource.cpp.fixed` is the verbatim fixed blob
(`6b80d6bd4be5eaf8923ddefb8501063cab74fa8918b67691dfd02ae3fa3c344d`); the
patch is `7bbe420e829b0d4968030d0ab7a016c65d181cb431983a8bff59f18c5edf54ac`.
All three hashes are in `lab/frontier/live555vorbis2shell/pins/PIN_HASHES.txt`.

In the raw pre-fix file: `:121` `ADVANCE(n)` subtracts unsigned `rem`;
`:122` `GET_ENCODED_VAL` decodes variable-length sizes; `:135` `base64Decode`
returns an exact-size heap buffer; `:137/:140/:142/:145/:148` are the only
length guards before the copies; `:149` reads the 16-bit `length`; `:152/:160`
decode header counts/sizes with only `headerSize > length` at `:161`; `:165`
makes the last header size the implicit remainder; `:171/:174/:177` allocate
the three header buffers. The unchecked copies are at raw lines **186** (ident),
**188** (comment) and **190** (setup). The fixed pin adds guards at raw
`:186/:190/:194` and moves the memmoves to `:187/:191/:195`.

**Line-number correction preserved:** the patch hunk header says
`@@ -183,13 +183,16 @@` and a read-only scout repeated `:183/185/187`; those
are patch-relative, exactly three lines short of the raw pinned blob. The
harness `#line 119 "liveMedia/VorbisAudioRTPSource.cpp"` maps the copied bytes
to raw lines 119-197/200, and the ASan checks assert raw `:186/:188/:190`.
Raw pinned bytes and the fix hunk are authoritative, not the hunk header.

The wired path claimed by the advisory (`a=fmtp config=` → SDP parser →
`parseVorbisOrTheoraConfigStr`) is **not** harnessed; only the parser function
is. No RTSP server, socket, full live555 build or client is used.

## Local observation (2026-11-26 W296, GCC and clang ASan, loopback-free)

`gen_sink.py` copies raw pinned lines 119-197 (vulnerable) and 119-200 (fixed)
byte-for-byte into `h/sink_vuln.cpp` / `h/sink_fixed.cpp`; `h/driver.cpp` is
frontier-authored scaffolding providing an exact-size libc base64 decoder and
a direct call. `run-all.sh` verifies the verbatim slices, all three pin hashes
and the fixed/safe controls, then rebuilds four GCC and one clang binary.

Vectors (unpadded base64 → decoded bytes):

| case | config | decoded hex | copy state |
|---|---|---|---|
| A | `AAAAAQAAAP//AKq7` | `00000001000000ffff00aabb` | identSize=65535, rem=2 |
| B | `AAAAAQAAAP//AQHM` | `00000001000000ffff0101cc` | commentSize=65534 after a 1-byte ident copy |
| C | `AAAAAQAAAABkAgEB3d3d` | `000000010000000064020101dddddd` | setupSize=98 after two 1-byte copies |
| SAFE | `AAAAAQAAAAAIAQIDQUJDREVGR0hJ` | `000000010000000008010203414243444546474849` | 8 declared bytes, 10 remain |

GCC ASan (`runs/asan-vuln-{a,b,c}.out`, rc 1 each):
`ERROR: AddressSanitizer: heap-buffer-overflow`, `READ of size 65535` at
`liveMedia/VorbisAudioRTPSource.cpp:186` from a 12-byte region;
`READ of size 65534` at `:188` from a 12-byte region; `READ of size 98` at
`:190` from a 15-byte region. Each fault is 0 bytes past the base64Decode
allocation. clang ASan reproduces the A read at `:186:7`.

Controls: fixed pin on A/B/C and SAFE on the vulnerable pin are ASan-clean
(rc 0); plain vulnerable A exits **0** on this build. Preserved negative:
no rung-1 crash and no rung-2 state failure was observed in the plain build.
`run-all.sh` **PASS=9 FAIL=0** at 22:40Z (`runs/run-all.log`).

## Rung-4 feasibility (honest)

- **Rung 1 and rung 2 NOT CLAIMED.** Plain build exits 0 on every vector; no
  deterministic crash or accounting failure was observed.
- **Rung 3 ASan confirmed** on all three verbatim pinned memmoves, with GCC
  and clang (A), fixed and safe controls clean.
- **Rung 4 NOT CLAIMED.** The harness prints only header sizes, not the bytes
  read past the buffer. No chosen offset, chosen leaked value, neighbouring
  object, pointer control, marker or command was observed. Advisory-level
  "leak heap memory" remains a claim, not a measured local readback.
- **Rung 5 NOT CLAIMED.** No wire path, RTSP server, live client or remote
  command; the sink is called directly from a local argv string.

## Cheapest local experiment that could move this up a rung

1. Modify the harness driver to print the three destination buffers after the
   copies and show attacker-chosen bytes read from past the base64Decode
   allocation; a measured chosen-byte readback would be rung 4 in the
   extracted harness only, still not a live-client claim.
2. Build the pinned 2026.08.24 live555 RTP client and replay an SDP
   `a=fmtp config=` against a loopback RTSP server this plant starts; observe
   a vulnerable/fixed differential (rung 2) and any heap bytes visible to the
   client (rung 4) with the fixed control from the mirror commit SHA.
3. Resolve why the plain build exits 0 (exact-size malloc slack) before
   claiming crash-based reachability. Never relabel an ASan OOB read as RCE.

## Ranking note (W296)

Two read-only scouts re-verified the claim and fix independently. No charter,
wall, window, lab directory or brief for live555 existed before this wake; it
is not in the frontier do-not-duplicate list. Its sink needs only libc
`malloc`/`new[]` and `memmove`, so rung 3 was cheap. The gate on rung 4 is
measured readback plus a real SDP consumer, not more ASan traces.
