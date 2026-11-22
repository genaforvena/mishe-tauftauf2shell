# Frontier brief: libvncclient Tight — GHSA-v9pm-47h4-jcq8 / CVE-2026-50538 (libvnc2shell)

Status W123 (2026-11-22): screened in and staged at rung 3 (ASan-confirmed heap
out-of-bounds write in a verbatim pinned function) plus rung 4 (chosen bytes at
a chosen offset in the adjacent heap region, direct-call/stub scope). Duplicate
check before provisioning: no prior `reports/frontier-*libvnc*`, no libvnc
window, charter or mind on the tape, and LibVNC is not on the do-not-duplicate
list in `walls/frontier.md`. **Ceiling note:** the victim is a *connecting VNC
client*, not a server; the attacker is the server or a man-in-the-middle, and
the advisory scores `UI:R`. The operator owns final admission; wake units and
full-flag sync stay with the person.

## 1. Verified ground truth

- Claim: GHSA-v9pm-47h4-jcq8, "Attacker-controlled heap out-of-bounds write in
  libvncclient Tight decoder", CVE-2026-50538, published 2026-05-29 by `bk138`,
  High / CVSS v3.1 8.8 (`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`).
- Claim source read (read-only provisioning, no external probe):
  `https://github.com/LibVNC/libvncserver/security/advisories/GHSA-v9pm-47h4-jcq8`.
- Affected: `libvncclient` 0.9.12 through current master `5ea5fc30` (0.9.15+).
  Introduced by `d7b1462` (2018-01-22, "Include Tight decoding optimizations
  from TurboVNC"); releases before 0.9.12 shipped a different decoder that was
  not assessed.
- **Fix-status discrepancy, recorded not corrected:** the advisory says
  "Patched versions: None", but upstream commit
  `540332be3e0acc566fa64da6f1b4680c72c724dd` (2026-05-29, "Merge commit from
  fork", parent `73352b9de9c0`) adds exactly the advisory's suggested clamp. No
  release tag carries it yet, which likely explains the advisory's field. Both
  pins are real repository commits and differ by only that 10-line hunk.
- Primitive claimed: a malicious/mitm server sends one `FramebufferUpdate`
  with a legal 16x16 Tight rectangle whose zlib stream decompresses to more
  rows than the declared height `rh`. `filterFn()` writes straight into
  `client->frameBuffer`, so rows past `rh` go past the allocation. The advisory
  demonstrates a default-build ASan crash and claims a separate callback-
  pointer overwrite / control-flow hijack; the latter is a claim, not a
  locally repeated observation (see section 4).
- Tight is advertised by default when zlib + libjpeg are enabled (CMake
  `WITH_ZLIB`/`WITH_JPEG` default ON), so no unusual client configuration is
  needed.

## 2. Source-bound mechanism and fix

In the vulnerable pin, `HandleTightBPP()` in `src/libvncclient/tight.c`
decompresses in a loop and calls `filterFn()` on each batch of rows. The row
count is derived purely from the decompressed byte count:

```c
numRows = (bufferSize - zs->avail_out) / rowSize;
filterFn(client, rx, ry+rowsProcessed, numRows);
extraBytes = bufferSize - zs->avail_out - numRows * rowSize;
rowsProcessed += numRows;
```

`rowsProcessed` is never compared with `rh` inside the loop. With the default
(no explicit filter) path, `filterFn` is `FilterCopyBPP`, whose body is
`memcpy(&dst[y*client->width], &client->buffer[y*rectWidth*(BPP/8)],
rectWidth*(BPP/8))` with
`dst = (CARDBPP *)&client->frameBuffer[(srcy*width+srcx)*BPP/8]` and
`srcy = ry+rowsProcessed`. The per-rectangle check at `rfbclient.c:~2252`
validates only the *declared* `rw`/`rh`, so a 16x16 rectangle in a 16x16
framebuffer passes and the over-expanding payload writes rows 16..N past the
1024-byte framebuffer. The existing `if (rowsProcessed != rh)` check at the end
of `HandleTightBPP()` runs after the writes and is too late.

The fix adds a pre-write clamp inside the loop (verbatim in the pin diff):

```c
if (numRows > rh - rowsProcessed) {
        rfbClientLog("Tight: too many scan lines after decompression.\n");
        return FALSE;
}
filterFn(client, rx, ry+rowsProcessed, numRows);
```

Sibling decoders already clamp this way (`trle.c` uses `while (j < h ...)`;
the Tight JPEG path uses `for (j = 0; j < h; j++)`), so the fix matches house
style. Commit `5b27054` ("fix Tight gradient decoding overflow", May 2026)
clamps rectangle *width* for a different stack overflow and does **not** fix
this row-count bug.

## 3. Measured evidence (this lab)

Everything lives in `lab/frontier/libvnc2shell/`. `harness/gen_fn.py` extracts
`HandleTightBPP`, `InitFilterCopyBPP` and `FilterCopyBPP` byte-for-byte from
each pinned `tight.c` (275 verbatim lines per pin). `harness/harness.c`
supplies a minimal `rfbClient`, a scripted `ReadFromRFBServer`/`ReadCompactLen`
and real zlib `inflate`. No socket, client or server is started. Full detail
and hashes: `harness/PROVENANCE.md`, `src/PIN_HASHES.txt`,
`harness/EVIDENCE_HASHES.txt`, `harness/evidence/norm-*.log`.

`bash lab/frontier/libvnc2shell/harness/run.sh` — **20 PASS / 0 FAIL**, `rc=0`,
two rounds with byte-identical normalized hashes (gcc 13.3.0 + clang 18.1.3):

- Vulnerable pin, 32 decompressed rows into a 16-row (1024-byte) framebuffer,
  gcc ASan: `ERROR: AddressSanitizer: heap-buffer-overflow`, `WRITE of size
  64`, `0 bytes after 1024-byte region`, frames `FilterCopy32` ->
  `HandleTight32` -> driver. clang ASan agrees on the fault and offset.
- Plain build (`FB_ALLOC=2048`, same overflow length): the adjacent region at
  offset 1024 reads `4142434445464748494a4b4c4d4e4f50` with chosen base
  `0x41` and `5a5b5c5d5e5f60616263646566676869` with `0x5a` — attacker-
  controlled bytes at a chosen offset, not incidental register values. The
  post-loop `Incorrect number of scan lines...` message fires only after the
  write, confirming the check is too late.
- Fixed pin with the same 32-row input: logs `Tight: too many scan lines after
  decompression.`, returns before `filterFn`; no ASan fault, adjacent region
  stays all zero (gcc and clang).
- Safe control (16 decompressed rows into a 16-row framebuffer): clean and
  returns TRUE on both pins (gcc and clang).

Nuance: the advisory's PoC reports `WRITE of size 4` through the `cutZeros`
(RGB24-to-pixel) branch of `FilterCopyBPP`; this harness uses the
`cutZeros=FALSE` plain-memcpy branch (`WRITE of size 64`). Same loop, same
missing clamp, different filter variant. Both are recorded rather than
presenting one as the other.

## 4. Honest ceiling / rung-4 feasibility

Reached: rung 3 (ASan-confirmed heap corruption in verbatim pinned code) and a
scoped rung 4 (chosen bytes at chosen offsets, direct-call/stub scope).
**Not** reached: no live `libvncclient` process, no RFB wire, no malicious
server, no `FramebufferUpdate`, no callback-pointer overwrite, no pointer
control, no marker execution, no command and no rung 5. The advisory's
control-flow-hijack demonstration depends on an application whose framebuffer
sits next to a callback pointer (its SDL/GTK/Qt example setup) and on an
information leak for ASLR; neither was reproduced here. The advisory's
`UI:R` and client-side victim position are unchanged.

Cheapest next experiments for the owning mind, in order: (1) replay the
advisory's private `evil_server.py` + ASan harness shape on a plant-started
loopback VNC server to move from direct-call to live wire (rung 4 at wire
scope); (2) measure the framebuffer-to-callback adjacency in the shipped SDL
example under a plant-started build; (3) only then consider whether a benign
marker redirect is reachable without an external leak. Rung 5 stays additive
and per-build.

## 5. Ranking and disposition

Tractability: high — a single self-contained function, a small two-pin diff,
real zlib locally, no client build needed for the current evidence. Ceiling is
honest but limited (client-side, `UI:R`, no pointer control). Staged by frontier
at 2026-11-22 21:17Z with a brief, charter, seed wall and a live two-pane
window; the operator owns final admission. Frontier owns no further work on
this lane after staging.
