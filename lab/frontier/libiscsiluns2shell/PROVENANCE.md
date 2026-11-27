# libiscsiluns2shell — provenance

## Claim source (read-only provisioning)

- Benjamin Ali advisory "Out-of-bounds reads and a write in libiscsi SCSI
  data-in unmarshalling", published 2026-08-04:
  https://benjaminali.com/advisories/libiscsi-scsi-datain-oob/. Product
  `libiscsi` (sahlberg), severity high, status fixed. No CVE or GHSA was
  assigned as of 2026-11-27: **CVE/GHSA UNKNOWN**, not invented.
- Advisory text: "**OOB WRITE — REPORT LUNS** (`scsi_reportluns_datain_unmarshall`,
  `:590`, CWE-787). `list_size < 8` makes `num_luns = list_size/8 - 1 = -1`;
  the alloc wraps to 2 bytes, then `list->num` writes 4 bytes into it. Reject
  `num_luns < 0` before the alloc." It states the paths are reachable from a
  malicious iSCSI target's data-in reply (INQUIRY / REPORT LUNS early in any
  session). No external target was contacted; all observations are local.
- Fix commit `eff2822fd1650c6348f872df38ec8a01377e3958` ("fix several
  vulnerabilities parsing data-in", 2026-08-03), read from
  https://github.com/sahlberg/libiscsi/commit/eff2822fd1650c6348f872df38ec8a01377e3958.
  Its REPORT LUNS hunk adds `if (num_luns < 0) { return NULL; }` before the
  allocation; the same commit bounds six other data-in decoders, which are
  separate claims not staged here.

## Pinned bytes

- Vulnerable `ef5491376fbae41a0512f06ae2471909523d49d9` (direct parent of the
  fix; advisory also verified `65ebd1415455d5016043a437aeec75e57b3bf043`).
  `pins/vuln.tar.gz` SHA-256 `ca0627817105e877b6271afef32b5c526d4f39445fef1b339ceb0721b81429cd`.
- Fixed `eff2822fd1650c6348f872df38ec8a01377e3958`.
  `pins/fixed.tar.gz` SHA-256 `30ac4625b936872aea695f0d80ec0beaf9428cb71841ae67002ba6863fce3678`.
- Reference hunk `pins/fix.patch` SHA-256
  `6620c1cb4afff0c061c024dc3c7f109988ee85c58f930332cdae341742ac3cea`, derived
  from `git diff` between the two pinned trees. Builds use the fixed tarball,
  not a patched build.
- Six harness/pin/build-script hashes are in `HARNESS_SHA256.txt`, checked by
  the clean-archive replay below.

## Source-bound mechanism

Vulnerable `lib/scsi-lowlevel.c:576-590`:

```c
if (task->datain.size < 4)
    return NULL;
list_size = task_get_uint32(task, 0) + 8;
if (list_size > task->datain.size)
    list_size = task->datain.size;
num_luns = list_size / 8 - 1;
list = scsi_malloc(task, offsetof(struct scsi_reportluns_list, luns)
                   + sizeof(uint16_t) * num_luns);
...
list->num = num_luns;
```

A four-byte REPORT LUNS reply gives `list_size = 4`, `num_luns = -1`, and an
allocation size of `sizeof(void*) + 4 - 2 = 10` bytes; `list->num` writes four
bytes at offset 8 of that 10-byte allocation. The harness sets the CDB opcode
to `SCSI_OPCODE_REPORTLUNS` (0xA0), heap-allocates the four-byte data-in blob
and calls the public `scsi_datain_unmarshall()` — the same dispatch used by a
real client receiving a target reply (`lib/scsi-lowlevel.c:3851`).

## Build and observation

`bash bootstrap.sh` extracts each tarball into its own tree, runs
`autoreconf -fi`, configures in-tree with `--disable-werror --disable-tests
--disable-examples --disable-test-tool --disable-manpages`, and builds four
variants (in-tree avoids an out-of-tree libtool `libiscsi.syms` path bug: the
first bootstrap attempt failed at that link and was replaced, not hidden).
ASan builds use `-O0 -g -fno-omit-frame-pointer -fsanitize=address
-fno-sanitize-recover=all`; plain builds use `-O0 -g -fno-stack-protector
-D_FORTIFY_SOURCE=0`. `run-all.sh` compiles the harness against each static
library and runs data-in sizes 4 (attack), 8 and 16 (safe controls).

Observed in `runs/`: vulnerable ASan exits 1 with
`ERROR: AddressSanitizer: heap-buffer-overflow`, `WRITE of size 4`, sink
`lib/scsi-lowlevel.c:590` via `scsi_datain_unmarshall:3851`, `0 bytes after
10-byte region [...,...)` allocated in `scsi_malloc:113` at `:584`. Vulnerable
plain prints `num=4294967295 (-1)` for the four-byte reply, an observed LUN
accounting failure from the wrapped allocation. Fixed ASan/plain return
`unmarshall=(nil)` for size 4. Sizes 8 and 16 are clean on all four variants
(`num=0`, `num=1`). `bash run-all.sh` returns rc 0 with
`TOTAL: 12 PASS / 0 FAIL`, summary SHA-256
`d97043e14f911935a204b70767e3ac002416078e56edee7db47316a0a28c44ff`.

## Grade and limits

R1 ✓ deterministic four-byte trigger. R2 ✓ negative LUN count in the plain
build and the exact ASan 10-byte allocation. R3 ✓ ASan-confirmed heap
WRITE-4 at the pinned sink. R4 LIMITED — the written value is the fixed
`-1`, not attacker-chosen bytes; no adjacent object, pointer or control-flow
state was measured. R5 NOT CLAIMED — no live loopback iSCSI target, saved RIP,
marker or command side effect. The advisory's six companion OOB reads are not
claimed here. The advisory supplies no CVE/GHSA; that field stays UNKNOWN.

## Candidate context (W333 scouts, not staged here)

NanoMQ CVE-2026-73863 / GHSA-pf97-vm7h-q84m pre-auth MQTT v5 SUBSCRIBE heap
OOB READ (tag 0.24.12 `486fbf58`, NanoNNG fix `f888fe39`, published PoC);
samtools GHSA-vh3p-9c59-j3hv `-G` read-group `fscanf("%s")` stack write (tag
1.24 `dc71c727`, one-character fix `bd8b5dc8`); SIPp CVE-2026-90779
`algorithm=` stack write (v3.7.7 `369b3c18` -> fix `1d4a5622`); bincookie
CVE-2026-55246 heap OOB read/write (v0.1.8 `cd72400e` -> `bc1433c1`), header
only and cheapest to harness; svxlink GHSA-5g48-xjmf-7p4q `setData()` stack
write; WavPack PR #242; OpenColorIO CVE-2026-42450; ngtcp2 CVE-2026-40170;
TDengine CVE-2026-62349/62351. pmacct issue #934 remains rejected: its cap
of 128 does not exclude the reported len=50, so no fixed control is pinnable.
