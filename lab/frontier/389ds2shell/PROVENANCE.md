# Provenance — 389ds2shell frontier harness

Fetched 2026-11-21 from primary sources only (OSV/CVE/GitHub APIs and
raw.githubusercontent.com). No external host was probed. All testing is local;
the harness opens no socket and starts no daemon.

## Pinned source bytes (sha256)

| Artifact | sha256 | Note |
|---|---|---|
| `pins/advisory.json` | `a03a6156d71594fc2a596b012c84574125734f5f747b3e1623b2b83209b44431` | GitHub advisory API, GHSA-2g8g-f92j-g4gq, CVE-2026-11610 |
| `pins/cve.json` | `1be123890bb0da43cc9ba03a55f403e2fb648e9504030a1bbddfcf1fde2aa4f5` | cveawg.mitre.org CVERecord, affected 1.3.2 through 3.3.0 |
| `pins/issue7658.json` | `6163717e3d5d3951643b7164a3746652b3f88ff1c799c3d9b4dcca897b493ab9` | upstream tracker, names `sasl_io_recv()` and the missing `encrypted_buffer_count <= len` check |
| `pins/fix.json` | `6b251fb60bac1b12c119a46141177c6ec7f6da48be77ed1d047d0483635bb00e` | GitHub commit API |
| `pins/sasl_io.c.e63592d5e6b0` | `9cea2e7bf22b1d8cd1296378c1416c63fdede17e4966466d2fd33e19318d84f3` | vulnerable parent, 30489 bytes |
| `pins/sasl_io.c.f15ffd63e2bd` | `f82aa846fbd2c6f07315e73a862042621184e8df1667b29f07db3be2333ea38b` | fixed commit, 31934 bytes |
| `gen_driver.py` | `7ad76f95771c684f5d3752ae0cc55fec198e3700c68e3d3d355b04085063527c` | generator; verified dynamically by `run.sh` |
| `run.sh` | `efbaa8b2a59f2e5a15d63e80bdcf4bffd3bba673557d5dfd1e5e497e420060f7` | runner at the recorded result |

Git pins: fix `f15ffd63e2bd70b3244881424ef903f17f7f0394` (committer
`2026-08-13T16:53:25Z`, "Issue 7658 - Heap Buffer Overflow in sasl_io_recv()
via Padded SASL UNBIND"), parent
`e63592d5e6b0c69ecb2799db3904743b9202b64d`. A separate commit `dd16813` fixes
CVE-2026-78701 (integer wrap in `sasl_io_start_packet`) and is explicitly
**not** this fix; it was read and excluded.

## Verbatim source ranges

`gen_driver.py` slices exact 1-based inclusive line ranges from the two pinned
files and asserts that each contains its distinguishing statement; generation
fails if a pin is edited or replaced:

- vulnerable `sasl_io.c:451-458` — the `SASL_IO_BUFFER_NOT_ENCRYPTED` branch
  containing `memcpy(buf, sp->encrypted_buffer, sp->encrypted_buffer_count)`
  (pinned line 456) and `return sp->encrypted_buffer_count;` (457). Emitted
  under `#line 451 "pins/sasl_io.c.vuln"`.
- fixed `sasl_io.c:156-182` — `sasl_io_drain_unencrypted_buffer()` with the
  `bytes_to_copy = (uint32_t)len` cap (line 170) and the offset-aware bounded
  `memcpy` (172). Emitted under `#line 156 "pins/sasl_io.c.fixed"`.
- fixed `sasl_io.c:476-478` — early `unencrypted_buffer_ready` drain.
- fixed `sasl_io.c:493-499` — fixed `SASL_IO_BUFFER_NOT_ENCRYPTED` branch.

The pinned struct fields (`encrypted_buffer`, `encrypted_buffer_count`,
`encrypted_buffer_offset`, plus fixed `unencrypted_buffer_ready`) and the
constants `SASL_IO_BUFFER_SIZE`/`SASL_IO_BUFFER_NOT_ENCRYPTED` are copied from
the same files (`sasl_io.c:25-27`, `:39-56`; fixed `:56`) into the generator's
scaffold.

## Harness-owned code (not upstream)

- `sasl_io_start_packet()` stand-in: returns `SASL_IO_BUFFER_NOT_ENCRYPTED`
  after setting `encrypted_buffer_count` from the simulated wire length and
  filling `encrypted_buffer` with a chosen pattern. Upstream
  `sasl_io_start_packet()` derives that count from the BER-declared packet
  length; the upstream issue's own test sets `PADDED_UNBIND_SIZE = 9000`, which
  this harness uses as `WIRE_COUNT`.
- `sasl_io_recv()` scaffold around the verbatim block: a caller buffer of 512
  bytes (`CALLER_LEN`, matching the advisory's 512-byte receive buffer),
  `bytes_in_buffer == 0`, and no decrypted data, so execution reaches the
  copied branch. The fixed build additionally honours the pinned early drain.
- Rung 4 collaborator: 1 MiB anonymous RW mapping used as `buf`; chosen `0x5a`
  or `0x41` in the wire buffer; offsets are counted from byte 512. The guard
  case maps two pages, makes the second `PROT_NONE`, and places `buf` so the
  copy crosses it; the SIGSEGV handler writes `guard_fault=1` and exits 77.
  Neither construct is an upstream allocator property.
- Cleanup frees allocations so LeakSanitizer does not mask the ASan result.
  A harness-owned `buf_is_heap` flag (set only after the ASan/benign
  `malloc`) gates `free(buf)`; collab and guard use an mmap base or an
  interior pointer, released with `munmap(mapping, mapsz)` instead.

## Repairs during construction (kept as evidence)

1. First generation nested the fixed drain function inside `sasl_io_recv` and
   omitted `-DFIXED`; compilation failed. Fixed by emitting the drain at file
   scope and compiling fixed drivers with `-DFIXED`.
2. An edit accidentally removed the pin-check and generation lines from
   `run.sh`, producing "No such file or directory" for the generated driver;
   both steps were restored.
3. Clean runs exited 1 under LeakSanitizer despite no memory error; added
   explicit cleanup. A grep string also expected `after a 512-byte region`
   while ASan prints `after 512-byte region`; corrected.
4. Compile warnings about the ignored `write()` return in the signal handler
   are harmless and remain visible on stderr.
5. Witness #740: unconditional `free(buf)` in the generated cleanup hit an
   mmap base (collab, rc=139) and a guard interior pointer (no-overflow guard,
   rc=134, `free(): invalid pointer`). Added the harness-owned heap flag so
   only malloc-backed buffers are freed; printed chosen-byte counts were
   unaffected because they are emitted before cleanup.

## Result

`cd lab/frontier/389ds2shell && ./run.sh`: **19 PASS / 0 FAIL**, rc 0, normalized
trace `sha256=5ac6faaeec38553369518aae643572de70cdfd0d5e9bd2ab2356220a968ba6f6`.
The ASan frame is `sasl_io_recv pins/sasl_io.c.vuln:456`, `WRITE of size 9000`,
`0 bytes after 512-byte region`; declared 511/512 are clean and 513 faults;
chosen bytes 0x5a/0x41 occupy offsets 0-8487 past the 512-byte boundary in the
collaborator, benign and fixed builds write none, guard page faults at exit 77.
The added checks assert rc=0 for `vuln_collab_5a`, `vuln_collab_41`,
`vuln_collab_benign` and `fixed_collab`, and rc=77 for the guard fault case.
The overflow write and chosen-byte offsets are unchanged from the pre-fix
run; only cleanup and exit-status hygiene changed.
