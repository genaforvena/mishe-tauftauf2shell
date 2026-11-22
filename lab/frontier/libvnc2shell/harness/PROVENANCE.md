# Provenance — libvnc2shell (GHSA-v9pm-47h4-jcq8 / CVE-2026-50538)

All source was fetched read-only from public GitHub during W123 provisioning
(2026-11-22). No external host was probed; no VNC client or server was started;
the RFB input is an in-process scripted byte stream.

## Pins and fix

| role | commit | file | SHA256 |
| --- | --- | --- | --- |
| vulnerable | `73352b9de9c0` (parent of the fix) | `src/tight-vuln.c` | `45dec2a5661594657dd7ff97f6f23fe6aca417938c0de42974f72599b3f41247` |
| fixed | `540332be3e0acc566fa64da6f1b4680c72c724dd` | `src/tight-fixed.c` | `b323d044f0ee88701a3a5055eaf630eb5975a8df6fdaac47ddb5dd313cc6dc6f` |

Fetch commands:

```
curl -fsSL -o src/tight-vuln.c \
  https://raw.githubusercontent.com/LibVNC/libvncserver/73352b9de9c0/src/libvncclient/tight.c
curl -fsSL -o src/tight-fixed.c \
  https://raw.githubusercontent.com/LibVNC/libvncserver/540332be3e0acc566fa64da6f1b4680c72c724dd/src/libvncclient/tight.c
```

`src/PIN_HASHES.txt` holds both hashes in `sha256sum --check` form and is
verified at the top of `harness/run.sh`. The two pinned files differ by exactly
the 10-line upstream clamp (no other delta):

```
$ diff -u src/tight-vuln.c src/tight-fixed.c
@@ -341,6 +341,16 @@ HandleTightBPP (rfbClient* client, int rx, int ry, int rw, int rh)
       numRows = (bufferSize - zs->avail_out) / rowSize;
+      if (numRows > rh - rowsProcessed) {
+        rfbClientLog("Tight: too many scan lines after decompression.\n");
+        return FALSE;
+      }
       filterFn(client, rx, ry+rowsProcessed, numRows);
```

The fix commit `540332be3e0a` ("Merge commit from fork", 2026-05-29, parent
`73352b9de9c0`) is the upstream landing of the advisory's suggested clamp.
The advisory's "Patched versions: None" line is stale: the fix is in the
repository but no release tag carries it yet. That discrepancy is recorded, not
silently corrected.

Support constants were fetched from the same vulnerable pin:
`include/rfb/rfbclient.h`, `include/rfb/rfbproto.h`,
`src/libvncclient/rfbclient.c` (`RFB_BUFFER_SIZE=640*480`,
`ZLIB_BUFFER_SIZE=30000`, `rfbTightMaxSubencoding=0x0A`, etc.).

## Harness inventory

- `harness/gen_fn.py` — extracts `HandleTightBPP`, `InitFilterCopyBPP` and
  `FilterCopyBPP` verbatim from a pinned `tight.c` (275 lines each pin). No
  logic is rewritten; only exact byte ranges are cut between anchors.
- `harness/harness.c` — minimal `rfbClient` stub, scripted `ReadFromRFBServer`
  and `ReadCompactLen`, real zlib `inflate`, 16x16 framebuffer, chosen-byte
  decompressed plane. `FB_ALLOC=1024` gives ASan an exact-size heap region;
  `FB_ALLOC=2048` gives the plain build a readable adjacent region.
- `harness/normalize.py` — strips PIDs, addresses and ASan shadow rows so
  replay hashes are byte-identical.
- `harness/run.sh` — builds vulnerable and fixed pins under gcc/clang ASan and
  plain, asserts each observation, records normalized hashes.
- `evidence/norm-*.log`, `EVIDENCE_HASHES.txt` — replay-stable evidence.

## Observed result (20 PASS / 0 FAIL, two rounds, byte-identical hashes)

Vulnerable pin, `ROWS=32` decompressed into a 16-row framebuffer:
`AddressSanitizer: heap-buffer-overflow`, `WRITE of size 64`,
`0 bytes after 1024-byte region`, top frames `FilterCopy32` ->
`HandleTight32`. Plain build reads back `oob16=414243...4f50` for chosen base
`0x41` and `oob16=5a5b5c...6869` for `0x5a` — chosen bytes at offset 1024,
i.e. exactly past the declared framebuffer. The advisory's PoC reports
`WRITE of size 4` through the `cutZeros` (RGB24) branch; this harness uses the
`cutZeros=FALSE` memcpy branch (`WRITE of size 64`). Same loop, same missing
clamp, different filter variant.

Fixed pin: logs `Tight: too many scan lines after decompression.` and returns
before `filterFn`; no fault, adjacent region stays zero. `ROWS=16` safe
control is clean and returns TRUE on both pins. clang ASan cross-check agrees.

## Not observed here (ceiling)

No live `libvncclient` process, no RFB wire, no malicious server, no
`FramebufferUpdate`, no callback-pointer overwrite, no pointer control, no
marker execution, no command and no rung 5. The advisory's code-execution
demonstration and its ASLR/information-leak scope note remain claims.
