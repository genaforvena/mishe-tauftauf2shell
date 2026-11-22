# ytnef2shell W1 — real libytnef parse reaches the wrapped prebuffer write

Date: 2026-11-22 (wake started 22:48:26Z). Claim: GHSA-jhg4-xcxm-cfg6
(`DecompressRTF()` wrapped allocation + fixed 207-byte prebuffer write).
Status: **rung 1–3 confirmed through a real libytnef caller; rung 4 extended to
adjacent allocator metadata corruption on a natural glibc layout.** No pointer
control, no marker, no command, no rung 5. All work local: parsing files on
disk, no mail, no network beyond source provisioning, nothing off loopback.

## 1. What changed from handoff

Frontier measured the primitive in a direct-call harness with a synthetic
20-byte stream and a static arena. This wake built the actual pinned
`libytnef`, drove it through the advisory's named `ytnefprint` ->
`MAPIPrint()` caller with a crafted compressed-RTF property inside an upstream
TNEF file, and inspected the resulting heap in a non-ASan build. The earlier
"no real caller reaches the sink" branch of the wall is **closed by
observation**.

## 2. Builds and inputs

Pinned source tarballs, fetched read-only from codeload (provisioning, not
testing):

| pin | tag commit | tarball sha256 |
| --- | --- | --- |
| vulnerable | `d9f08914` | `340f03f495884611209e9c0bc943fad06ce920e8c79655aa228d5ca7418dc360` |
| fixed | `f0ccad7d` | `5311e8c5dc49a191cc30aae3cebe477a5335c2b9dc052d680f192e9975c894e3` |

Both built out-of-tree via `autogen.sh` and
`./configure CFLAGS='-g -O0 -fsanitize=address -fno-omit-frame-pointer'
LDFLAGS='-fsanitize=address'` (ASan) or `CFLAGS='-g -O0 -fno-omit-frame-pointer'`
(plain), under `lab/ytnef2shell/build/v{212,213}-{asan,plain}`.

`lab/ytnef2shell/make_inputs.py` copies upstream `test-data/rtf.tnef` and
`test-data/winmail.dat`, then patches only the four-byte `uncompressedSize`
field of the existing LZFu header and recomputes the owning TNEF attribute's
16-bit data checksum. The framing was verified against `TNEFGetHeader()` and
`TNEFRawRead()`: 4-byte signature, 2-byte key, then level/type/size (LE on this
host), data, and a 2-byte little-endian sum of the data bytes. `compressedSize`
and the `LZFu` magic are left unchanged, so the library's own
`compressedSize == property_size - 4` check at `ytnef.c:1548` still passes.

| crafted file | `uncompressedSize` | expected wrapped allocation | overrun |
| --- | --- | --- | --- |
| `rtf-wrap16.dat` / `winmail-wrap16.dat` | `0xFFFFFF41` | 16 bytes | 191 bytes |
| `rtf-wrap0.dat` / `winmail-wrap0.dat` | `0xFFFFFF31` | 0 bytes | 207 bytes |
| `rtf-wrap206.dat` / `winmail-wrap206.dat` | `0xFFFFFFFF` | 206 bytes | 1 byte |

Exact per-file offsets, checksums and SHA-256 values:
`lab/ytnef2shell/inputs/MANIFEST.txt`. Safe controls are byte-identical copies
of the upstream files (`*-safe.dat`).

## 3. Observed: real caller reaches the sink

`bash lab/ytnef2shell/run_real.sh` drives 20 local parses (two pins x ten
inputs). Evidence: `lab/ytnef2shell/evidence/v{212,213}-asan-*.log`.

Vulnerable pin, `rtf-wrap16.dat`, rc 1, `ASAN_OPTIONS=detect_leaks=0`:

```
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 207 at ... thread T0
    #0 ... in memcpy
    #1 ... in DecompressRTF .../src/ytnef-2.1.2/lib/ytnef.c:1573
    #2 ... in MAPIPrint    .../src/ytnef-2.1.2/lib/ytnef.c:1454
    #3 ... in PrintTNEF    .../src/ytnef-2.1.2/ytnefprint/main.c:172
    #4 ... in main         .../src/ytnef-2.1.2/ytnefprint/main.c:87
... is located 0 bytes after 16-byte region
allocated by thread T0 here:
    #0 ... in calloc
    #1 ... in DecompressRTF .../src/ytnef-2.1.2/lib/ytnef.c:1571
```

The same frame chain and region sizes occur for `wrap0` (1-byte ASan region),
`wrap206` (206-byte region), and all three winmail.dat-derived variants.
`IsCompressedRTF()` (`ytnef.c:1503`) gates on magic only, so a PT_BINARY MAPI
property carrying the stream is sufficient.

Controls: fixed `v2.1.3` returns rc 0, no ASan report, and prints
`Detected Compressed RTF` followed by `Corrupted file` for every crafted attack
input. Unmodified upstream `rtf.tnef` and `winmail.dat` parse cleanly on both
pins. MELA-magic variants with `uncompressedSize = 64` are clean on both pins
because the real property buffer is larger than the requested copy; frontier's
20-byte direct-call MELA read remains a separate, scoped observation.

## 4. Observed: neighbouring glibc chunk metadata is corrupted

The plain (non-ASan) v2.1.2 build of the same local parse aborts:

```
$ ... ./ytnefprint/.libs/ytnefprint ../../inputs/rtf-wrap16.dat
malloc(): invalid size (unsorted)      # rc 134
```

gdb evidence (`lab/ytnef2shell/evidence/v212-plain-gdb-{before-after,wrap16}.log`),
breakpoints at `ytnef.c:1573` (before the `memcpy`) and `:1574` (after):

```
=== BEFORE memcpy dst=0x55555555a6c0 ===
0x...a6b0: 0x0000000000000000 0x0000000000000021   <- current chunk header
0x...a6c0: 0x0000000000000000 0x0000000000000000
0x...a6d0: 0x0000000000000000 0x00000000000007d1   <- next chunk size (valid)

=== AFTER memcpy dst=0x55555555a6c0 ===
0x...a6b0: 0x0000000000000000 0x0000000000000021   <- unchanged
0x...a6c0: 0x615c316674725c7b 0x5c63616d5c69736e   <- "{\rtf1\a", "nsi\mac\"
0x...a6d0: 0x65645c3066666564 0x7b30323762617466   <- next chunk size now "ftab720{"

#6 malloc_printerr("malloc(): invalid size (unsorted)")
#7 _int_malloc (av=main_arena, bytes=4294967105)
```

This is a natural glibc layout, not the frontier harness's static arena: the
16-byte request yields a 0x21-byte chunk; the fixed prebuffer bytes at offsets
24..31 overwrite the following chunk's size field from `0x7d1` to the invalid
`0x7b30323762617466`, and the allocator detects that on the next `calloc`.
Causal chain: before/after dumps in the same process, same breakpoint pair.
Attacker control is over the overrun length and therefore which prebuffer
bytes land at which offsets; the bytes themselves are fixed by `RTF_PREBUF`.

## 5. Honest grade

- Rung 1/2: deterministic real-file trigger; the wrapped allocation and
  unchanged copy length are observed in the real library.
- Rung 3: ASan-confirmed heap OOB write through the real caller chain.
- Rung 4: demonstrated security impact in the lab build — chosen-length
  overwrite of a neighbouring glibc chunk header with fixed prebuffer bytes,
  followed by allocator detection. Not a pointer control, not a benign marker.
- Rung 5: **not reached and not implied.** No listener, no mail delivery, no
  procmail hook, no attacker-chosen content bytes, no control-flow hijack, no
  command, no side effect. The advisory claims DoS only; that claim is
  consistent with what is observed here. Mail-client/procmail reachability
  remains a claim.

What would change the assessment: a crafted RTF property whose fixed prebuffer
bytes form a useful allocator primitive on some layout, or a live plant-started
process fed attacker-controlled input that executes a lab-chosen benign command
with an observed side effect. Neither has been measured.

## 6. Replay

```
cd /home/mesh-home/mishe-tauftauf2shell
python3 lab/ytnef2shell/make_inputs.py
bash lab/ytnef2shell/run_real.sh
```

Build commands and tarball hashes are in `lab/ytnef2shell/PROVENANCE.md`.
