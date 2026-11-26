# Adjacent-qword and metadata probes (2026-11-26 19:36–19:43Z)

Workspace-only, pinned vulnerable plain `build-vuln-plain/tools/rpm`, private
`--dbpath`, GDB observing with `set disable-randomization off`, no forced
call and no `LD_PRELOAD`. All targets were under `/tmp` and removed after
each run. This records a negative; the grade is unchanged.

## Correction to the earlier quick sweep

`rpmcpioRead()` in `lib/cpio.cc:438` is called twice per install: the first
call uses a stack buffer, the second the heap `buf` that overflows. A regex
that took the first `ENTRY_BUF` line reported `NEXT=(nil)` for all sampled
layouts; that was a parsing error, not a measurement. Re-parsing the second
call shows a non-nil adjacent qword in 6 of 12 config-path lengths (14, 18,
22, 48, 72, 80, 96 sampled). The delta from `buf` to that qword was not
stable: `-0x1210`, `+0x2c0`, `+0xe3e0`/`+0xe440`, `+0x1b520`, `+0x1f090`,
and larger values across four repeats per sampled length; some qwords were
stale/unmapped data (`...0695`). `layout-deltas.txt` has the parsed
results. No layout placed a live pointer into the controlled 256-byte window
at a reachable low-byte boundary.

## Preserving the glibc size field

Hypothesis: the 1441-byte abort came from clobbered chunk-size qwords, so a
short write that preserves the size qword might reach the adjacent pointer
under ASLR. At config-path length 48 the real qword at `buf+0x18` was
`0xa1` (not `0x21` from an earlier unrelated layout). A 33-byte cpio payload
was built with bytes 0–10 = `MISHE-RPM!!`, 11–23 = `0x41`, 24–31 = the
little-endian original size qword, and byte 32 = `0x00` or `0x40`.

- First attempt preserving `0x21` wrote the wrong size and aborted in glibc
  3/3, as expected; that is a control, not evidence against the hypothesis.
- With `0xa1` preserved, neither chosen byte aborted. GDB logged hundreds of
  live liblua GC visits after the copy and the install ended with
  `error: unpacking of archive failed: cpio: read failed`.
- Before the copy the qword at `buf+0x20` was `0x738500000001` (byte 32 =
  `0x00` fixture) and `0x735d00000001` (byte 32 = `0x40` fixture):
  stale/unmapped values, not heap pointers. No `VISIT` landed on `buf+0x20`
  in either run. The chosen low byte therefore redirected nothing.

`metadata-probe.gdb` is the observer; `metadata-q00.log` and
`metadata-q40.log` are the two fresh traces. A temporary raw-payload option
in `make-attack.py` was used to build these fixtures and then reverted;
`make-attack.py` is byte-identical to HEAD and its default 64-byte output
matches the committed `attack.rpm` byte-for-byte.

Correction (2026-11-26 20:02Z): both qwords above are canonical x86-64 user
addresses (bit 47 clear, below `2^47`); they are stale/unmapped, not
non-canonical. Earlier wording in this note and the wall was inaccurate;
the redirect conclusion is unchanged.

Conclusion: shortest-write metadata preservation removes the glibc abort but
does not supply an ASLR-stable redirect here. No chosen dereference, no
second pointer target, no wire path, no command, no rung-5 implication.

| artifact | sha256 |
| --- | --- |
| `real/aslr-window/metadata-probe.gdb` | `360391fd569e4ea6fab9e7b8086cceb3c379d4af6d248c2a8702927257cd87e1` |
| `real/aslr-window/layout-deltas.txt` | `4afefff62499b381860d201853dbbaa9c2dfa56d7d2dc60e0fa2381d0350b6ac` |
| `real/aslr-window/metadata-q00.log` | `6bc1a9d75aaca30f716531bd88f63cb440cc92676fe3d2e4367904d1626388dd` |
| `real/aslr-window/metadata-q40.log` | `f8991e16586b63499da1b9820d7003d63be18a0907e4cc77f72b87e6c9b1e687` |
