# FastNetMon CVE-2026-48689 lab provenance

## What is here

A direct-call harness against the REAL upstream `dynamic_binary_buffer_t` class,
compiled from two pinned raw header files. No reimplementation of the class and
no daemon/wire traffic. The vulnerable pin is the fix commit's parent.

- `pins/dynamic_binary_buffer.vuln.hpp` — raw header at `97b04568b6f1...`
- `pins/dynamic_binary_buffer.fixed.hpp` — raw header at `fa80390ed446...`
- `pins/fix-48689.patch` — upstream PR 1051 patch
- `pins/PINS.txt` — URLs, full hashes, local sha256s, fix hunk
- `harness/poc.cpp` — 24-byte buffer, full `append_byte()` fill, then one
  chosen byte via `append_data_as_pointer()` at offset 24 (`max + 1`)
- `harness/run.sh` — builds 4 binaries (vuln/fixed × ASan/plain), replays two
  markers (0x41, 0x5a), normalizes logs and rewrites `EVIDENCE_HASHES.txt`
- `evidence/norm-*.log` — normalized replay output
- `out-*` — raw replay output (gitignored)

## How to replay

```
cd lab/frontier/fastnetmon2shell/harness && bash run.sh
```

Expected: vulnerable ASan aborts with `heap-buffer-overflow`, `WRITE of size 1`,
0 bytes after the 24-byte region, frame `append_data_as_pointer` at
`dynamic_binary_buffer.vuln.hpp:115`; fixed ASan is clean (`accepted=0`,
`failed_flag=1`); plain vulnerable readback shows `byte[24]` equals the chosen
marker; plain fixed rejects. Exit status 1 is expected for the ASan abort and
for the fixed rejection.

## Normalization

`==PID==` for ASan process ids, `0xADDR` for addresses of 6+ hex digits, `#FRAME`
for stack frame numbers. Short chosen-byte hex values (`0x41`, `0x5a`) are
preserved. PIDs, ASLR bases and frame numbering are volatile; the chosen byte
and the source line are not.

## Limits

Rung 3 (ASan-confirmed WRITE-1) and rung 4 at **direct-call harness** scope
(chosen byte at chosen offset in the plain build). No daemon was built, no
loopback listener bound and no NetFlow/BGP/sFlow packet sent. The blog's claims
that the buffer class is reachable from every wire protocol and that a glibc
heap-metadata overwrite leads to RCE are **claims**, not measured here.
The plain-build readback is deliberately skipped under ASan: reading the
out-of-bounds byte from the harness would produce a false READ report in the
fixed control (observed and corrected this wake).
