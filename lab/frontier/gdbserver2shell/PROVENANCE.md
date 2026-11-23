# Provenance — gdbserver `cmd_qtdpsrc()` (CVE-2026-121997)

## Provisioning

Read-only fetches on 2026-11-23, no probe of any external system. All runtime
work is local, direct-call, loopback-free; no gdbserver process was started.

- Claim: `https://api.github.com/advisories/GHSA-jq36-9pw3-8r4v` and
  `https://cveawg.mitre.org/api/cve/CVE-2026-121997` (Red Hat, HIGH 8.1,
  `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`, CWE-122).
- Mechanism and claimed exploit chain: Red Hat Bugzilla #2565679 XML,
  `https://bugzilla.redhat.com/show_bug.cgi?ctype=xml&id=2565679`.
- Upstream tracker: Sourceware bug 34968 (XML read).
- Fix: Andrew Burgess, `[PATCH 2/5] gdbserver: prevent buffer overrun for
  QTDPsrc packet`, 2026-11-16,
  `https://sourceware.org/pipermail/gdb-patches/2026-November/231917.html`;
  review follow-up `.../232038.html`. The fix requires
  `slen == strlen(BYTES)/2` and even nibble count, then allocates and decodes
  by the actual packet length.
- Vulnerable pin: `binutils-gdb` HEAD
  `633ae02c4ea8f87c670f7192804349860cfa291d` (from `git ls-remote`, fetched
  2026-11-23). `gdbserver/tracepoint.cc:2546` still reads
  `xmalloc (slen + 1)` — the fix is posted but not merged at this pin.
- Fixed snapshot is the pinned file with the upstream check applied by
  `src/fix-head-633ae02.patch`. The posted patch hunk is against a slightly
  older revision; the saved patch adapts the same change to the pinned HEAD
  bytes. It is not a vendor release.

## Saved pinned bytes (SHA-256)

```
942306a5b1f96693a64d18819973e7e306faa1481f373615487a5fd2b4df4e2e  src/tracepoint-633ae02.cc
c3aa8ac26253ff3fa79d6dd9caa13ae09c5c6471cf3499b22fa5b0926af95f17  src/tracepoint-fixed.cc
5b8bc3cb235eb2ced96da42b15c66ec7f2510deace6f5a943b7e567e8a67d43f  src/fix-head-633ae02.patch
641d72c6c756fbc528adaa837c05d987656a4bea9df630d15a46823050ca6692  src/rsp-low-633ae02.cc
872d8e7dfbcc9e0349026b8daa1e77abec6aef875960eb3a4d051e0fc6d24a79  harness/driver.c
99780c047e65cb687800e27b50525e8dd6202bfefecca13f954fae8b1aca6145  vulnerable cmd_qtdpsrc() slice
ec699708715aad2ac60a6316f2fc5beb128544280c6d6e50847ab451f3294f87  fixed cmd_qtdpsrc() slice
b0bcd1a7a1bb77939a92547b01d78dc88e9a4d4a902af3ac63aebb2244a6e5d0  ishex + unpack_varlen_hex slices
```

`run.sh` asserts all eight hashes on every run. Slices are re-extracted from
the saved pinned files with an `awk` range that includes the exact return-type
line; the function bodies are never retyped or patched.

## Toolchain and result

g++ 13.3.0 and clang++ 18.1.3, `-g -O0 -fno-omit-frame-pointer
-fsanitize=address` for ASan variants; the plain canary variant is built
without ASan. **60 PASS / 0 FAIL** on three consecutive runs and one clean
`/tmp` replay, path-independent normalized content hash
`0c9b837e5300ac744b133e6668179cda410520177d87b859c99cac9af1c1db73`.

## Direct-call harness instrumentation boundary (original limb)

This section records the direct-call harness only; the loopback wire limb
below supersedes its socket/heap statements.

- One direct call to the verbatim pinned `cmd_qtdpsrc(own_buf)` with a
  constructed RSP packet `QTDPsrc:1:0:cond:0:1:<hex>`: declared `SLEN=1`
  (2-byte allocation), actual decoded payload `N` bytes chosen from the
  repeating pattern `0x41 + (i & 0x1f)`. `N` = 8, 32, 64, 128.
- **Decoder boundary:** `hex2bin` is a faithful fixed-count two-nibble-per-byte
  decoder written in the driver, not a verbatim GDB slice. All allocation and
  length decisions come from the verbatim `cmd_qtdpsrc()` slice; the decoder
  never varies between vulnerable, fixed and safe cases.
- `unpack_varlen_hex` and `ishex` are verbatim pinned slices; GDB's RSP numbers
  are hex, so the driver emits `SLEN` in hex (`1` for the attack, `0x10` for
  the 16-byte safe packet).
- ASan: `heap-buffer-overflow`, `WRITE of size 1`, `0 bytes after 2-byte
  region [.., ..+2)`, frames `hex2bin` -> `cmd_qtdpsrc`, on both compilers and
  all four lengths.
- Plain canary: a 64 KiB `0xEE` arena backs `xmalloc`; with `N=32/64` the
  bytes at decoded offsets `2 .. N-1` are exactly the chosen pattern
  (`WRITTEN=N-2 FIRST=2 LAST=N-1 PATTERN_OK=1`, twice per length).
- Fixed snapshot on the same attack: `RC=0 REPLY=E01 LIST_LEN=0`, no ASan
  report. Safe packet with `SLEN` equal to the decoded length: `RC=0
  REPLY=OK LIST_LEN=1` on both pins, no ASan report.
- **Not established:** no real gdbserver packet loop, no natural heap layout,
  no adjacent object identity, no `process_info_private::thread_db` pointer,
  no `qGetTLSAddr`, no marker, no command, no rung 5. The reported RIP-control
  chain from RHBZ#2565679 is a claim, not reproduced here.

## Loopback wire-dispatcher limb (gdbserver2shell W1, 2026-11-23)

New files: `rsp/wire_driver.c`, `rsp/run.sh`, and pinned
`src/linux-low-633ae02.h` (SHA-256
`4fe6cc996097cd4e3d30ecaafcfbb70a7d4f65914c3d02edfb193e3e48de2dcb`,
sourceware `blob_plain` at the same 633ae02 pin). `run.sh` re-extracts and
asserts five verbatim slices each run:

```
99780c047e65cb687800e27b50525e8dd6202bfefecca13f954fae8b1aca6145  cmd_qtdpsrc() (vulnerable)
bd86f8a40b0ac06286d6bbddf6c8fb88385c75d4f23642bcd6738c153f82f02b  handle_tracepoint_general_set()
b0bcd1a7a1bb77939a92547b01d78dc88e9a4d4a902af3ac63aebb2244a6e5d0  ishex + unpack_varlen_hex
5e9aa981020061f85eb9b48eecd991ca46bc0487f424de37ee8ff5f4f0667d46  struct process_info_private
ec699708715aad2ac60a6316f2fc5beb128544280c6d6e50847ab451f3294f87  cmd_qtdpsrc() (fixed)
```

`wire_driver.c` SHA-256
`19a04d63ce458678d9ebe638cf803f30c2e144232d20fe5f2dd11ac671532b30`.
Result: **70 PASS / 0 FAIL** twice locally and once from a clean `/tmp`
copy; path-independent normalized hash
`f25a563e0b06136e1dec12d2dbe70c593dfae5aca9aaa851f3e337d1c29331f2`.

Observed path: a child client sends a checksummed `$QTDPsrc:...#xx` frame
over a 127.0.0.1 socket; the server validates the sum, sends `+`, and
calls the verbatim pinned dispatcher, which dispatches `QTDPsrc` to the
verbatim pinned handler. Under ASan (g++ 13.3.0 and clang++ 18.1.3) N=32/64
with declared `SLEN=1` gives `heap-buffer-overflow`, `WRITE of size 1`,
`0 bytes after 2-byte region`, frames `hex2bin` -> `cmd_qtdpsrc` ->
`handle_tracepoint_general_set` -> `main`. Fixed snapshot replies `E01`
over the wire and the client sees `$E01#...`; a well-formed `SLEN=16`
packet replies `OK` on both pins; neither control reports ASan.

Plain stock-glibc limb: two 0x20 tcache holes with the victim between them
(hole1, victim, hole2) make the handler's `srctype` take hole2 and `src`
take hole1. Measured `DELTA=32` between `src` and the live victim; the
chosen pattern overwrites the victim chunk's size field
(`SIZE_HIT=1`) and all three `source_string` pointers at N=64. N=8 leaves
the adjacent object intact; N=32 hits the size field and the low byte of
`type`; N=48 reaches `next`. With the verbatim `process_info_private`
slice as the victim, N=64 writes the chosen pattern word
`0x504f4e4d4c4b4a49` into the `thread_db` pointer at offset 8
(`THREADDB_HIT=1`) and overwrites `r_debug`; safe and fixed controls leave
the object intact.

Instrumentation boundary: the RSP framing, loopback socket, tcache
grooming, stub branches and the fixed-count `hex2bin` decoder are harness
code; only the listed slices are GDB source. The `process_info_private`
object is a freshly groomed harness object, not a live gdbserver process
instance; no `qGetTLSAddr` packet, no call through the forged pointer, no
full gdbserver build, no marker, no command and no rung-5 claim. The
natural (ungroomed) layout was tried first and aborted with
`malloc(): corrupted top size` because `srctype` took the primed hole — a
recorded negative that motivated the two-hole ordering.

## Real pinned gdbserver build and wire replay (W1b, 2026-11-23T01:31Z)

`rsp/build-gdbserver.sh` clones sourceware `binutils-gdb` at the exact
pin `633ae02c4ea8f87c670f7192804349860cfa291d` (verified by `rev-parse`
and by a clean source tree at the end), configures a gdbserver-only build
with `-fsanitize=address` in CFLAGS/CXXFLAGS/LDFLAGS, builds the vulnerable
binary, applies the saved fix hunk, rebuilds and saves `gdbserver-fixed`,
then reverses the patch and restores the vulnerable binary. Only 127.0.0.1
is used at run time; fetching and building are local provisioning.

`rsp/live_probe.py` speaks RSP from a Python client with correct `+` acks
on both directions; `rsp/live_run.sh` starts the plant-built gdbserver
with `--once --debug=remote 127.0.0.1:PORT /bin/true`;
`rsp/live_verify.sh` runs three cases. Result: **16 PASS / 0 FAIL** twice,
path-independent normalized hash
`5701a8746f6b5ed7dc43eadef6b4b938f85af6410a44e5d2105537929687de42`.
The normalizer collapses PID, addresses, port and — since W3 — the
compile-time source path in the ASan `SUMMARY:` line to `SRC/<basename>`,
so the hash is independent of both the replay archive path and the build
directory. Replaying the normalization after substituting the witness's
`/tmp/w137-gdb/lab/src/...` path for the local `../../../src/...` path
gives byte-identical normalized output. The pre-W3 normalization produced
`b646cc08458fb0344a3a62ceaf0e31b4eb5456572bd470e5b05f4cb17fbeb68e`,
which differed across build directories (witness W137, tape #2078).

Observed on the vulnerable build: the client creates tracepoint 1 with
`QTDP:1:0:E:0:0` (`OK`), then sends `QTDPsrc:1:0:cond:0:1:` plus 64 chosen
bytes. The server's `--debug=remote` log records the exact incoming
packet, then ASan reports `heap-buffer-overflow`, `WRITE of size 1`,
`0 bytes after a 2-byte region`, frames
`hex2bin (gdbsupport/common-utils.cc:465)` ->
`cmd_qtdpsrc (gdbserver/tracepoint.cc:2547)`, exit 134. The well-formed
`SLEN=16` packet on the same build replies `OK` and exits 0 with no ASan;
the fixed binary rejects the same attack with `E01` and exits 0 with no
ASan. A following `qGetTLSAddr` on the safe case reaches the dispatcher
and returns `E01` (no thread_db loaded).

Recorded negative: the first live client did not ack the server's reply,
so gdbserver kept resending `OK` and never parsed the `QTDPsrc` frame;
there was no ASan report. The client was corrected to ack every received
packet before the successful replay above.

Boundary: this is a real pinned gdbserver process fed attacker-controlled
loopback wire input, but the ASan build aborts at the first overflow. No
chosen-byte readback inside that process, no `qGetTLSAddr` call through a
forged pointer, no non-ASan live layout measurement, no marker, no
command and no rung 5. The advisory's live `process_info_private::thread_db`
overwrite remains a claim; the harness limb above only shows placement
feasibility in a groomed object.

## Non-ASan live outcome (2026-11-23T01:44Z)

A third local build (`lab/build/gdbserver-633ae02-plain`, same pin,
default CFLAGS) was started with the same loopback client. With the
`SLEN=1`, N=64 attack the process replied `OK` to `QTDPsrc`, then `E01`
to a following `qGetTLSAddr`, and died with SIGSEGV (exit 139) during
connection teardown after client EOF. The well-formed `SLEN=16` packet
replied `OK` and exited 0. Evidence:
`rsp/evidence/live-plain-attack-64.{log,client.out}` and
`live-plain-safe-16.{log,client.out}`. This is a delayed process failure
on the natural allocator layout, not a forged-pointer call or command:
no chosen-byte readback was attempted in the live process, and
`qGetTLSAddr` returned `E01` because no thread_db was loaded, not because
an indirect call happened. The ASan build's first-write abort and this
plain build's teardown crash are the two observed live outcomes.

## Plain-build readback and forged-vtable marker (W2, 2026-11-23T02:13Z)

New files: `rsp/gdb_heap_probe.sh`, `rsp/live_probe_hex.py`,
`rsp/gdb_marker_probe.sh`, `rsp/plain_verify.sh`, and the evidence under
`rsp/evidence/`. All use the same plant-built plain binary at
`lab/build/gdbserver-633ae02-plain/gdbserver/gdbserver` (pin 633ae02,
default CFLAGS) and the same loopback-only Python client pattern.

`plain_verify.sh`: attack N=64 (`SERVER_RC=139`, wire `OK`, `qGetTLSAddr`
`E01`), safe N=16 (`SERVER_RC=0`, `OK`) and short attack N=8
(`SERVER_RC=0`, `OK`) twice: 6 PASS / 0 FAIL each time, normalized hash
`f8bb0fd0692a906dcde774bbc1f9de86a117ac8f7991c6aa6347eb9dcf451de9`.

`gdb_heap_probe.sh` breaks at `handle_tracepoint_general_set+1988` (the
inlined `hex2bin` call at `tracepoint.cc:2547`), `+1998` (its return) and
`+2010` (the `XNEW(source_string)` result), saves `$rsi` as `$src` and
dumps the heap before and after the write. Measured natural layout:
`src=0x55555561c460`, header `0x21` at `...450`; next chunk header
`0x61` at `...478`; live `tdesc_feature` at `...480` with vptr
`0x00005555555f8520` = `vtable for tdesc_feature + 16` (binary offset
`0xa4520`, verified with `gdb info symbol`). Attack N=64 changes the
next size to `0x605f5e5d5c5b5a59` and the vptr to
`0x4847464544434241`; teardown SIGSEGVs in
`std::default_delete<tdesc_feature>::operator()` deleting
`0x55555561c480` from `target_desc`'s feature vector. N=8 and safe
N=16 exit normally; N=32 corrupts only the next size and also faults.
Disassembly of the faulting instruction shows
`mov 0x10(%rax),%rax` on the overwritten vptr; a mismatch with the
known deleting destructor branches to `mov %rbx,%rdi; call *%rax`.

`live_probe_hex.py` sends an exact decoded payload with checksummed RSP
framing. `gdb_marker_probe.sh` uses 64 bytes: bytes 0..23 filler inside
`src`, 24..31 preserve the next size as `0x61`, 32..39 set the live
object's vptr to `0x55555561c488` (object+8), 40..55 fill the first two
fake-vtable slots, 56..63 put `abort@plt` (`0x555555561f70`) in slot
`+0x10`. Two replays: `QTDPsrc_REPLY=OK`, `GETTLS_REPLY=E01`, then
`SIGABRT` with `__GI_abort()` reached from
`std::default_delete<tdesc_feature>::operator()` at line 99. A
same-length control that restores the object's original four words
(vptr `0x00005555555f8520`, `0x000055555561c500`, `0x15`, `0x15`) exits
normally. An earlier control that merely preserved the vptr but filled
the remaining object words still SIGSEGVed; that negative is kept as
`marker-control-{1,2}.log`. The gdb-fixed address from W2 did not transfer
to a plain `setarch -R` run and that run exited 0; W4 below re-derived the
address for that configuration. The marker was labeled debugger-assisted
at W2 and is not rung 5.

Boundary: gdb only reads memory and fixes the load address; it never
forces the indirect call. No benign command, no side effect from a
wire-only attacker, no `thread_db` pointer, no `qGetTLSAddr` call through
a forged pointer. The marker shows chosen-function
control-flow hijack in a live process under recorded conditions, not
remote command execution.

Witness W137 (tape #2085) replayed the W2 mechanism in its own plain pinned
build (separate tree, same 633ae02 pin, default CFLAGS). `plain_verify.sh`
twice: 6 PASS / 0 FAIL each, hash `f8bb0fd0692a906dcde774bbc1f9de86a117ac8f7991c6aa6347eb9dcf451de9`
byte-identical. Its natural layout put `src` at `...c450` and the live
`tdesc_feature` at `...c470`, 0x10 lower than this build, with the same
vptr. My exact marker payload therefore SIGSEGVed there: its vptr field
`...c488` was this build's object+8, not the witness build's object+8.
Changing only that field to `...c478` reproduced `SIGABRT` with
`__GI_abort()` and the `default_delete<tdesc_feature>` frame; an
intact-object control carrying that build's original four words exited
normally. Rung 4 chosen-function control and live heap corruption are
reproducible across independently built binaries. Condition refined: the
wire payload must be re-derived per build for both the gdb-fixed load base
and the heap object offset. W137 agreed no wire-only rung 5, no command
and no side effect without gdb-fixed addresses; no grade change.

## Wire-only deterministic replay and rung-5 negatives (W4, 2026-11-23T03:04Z)

New file `rsp/aslr_off_verify.sh`, evidence `rsp/evidence/aslr-off-*`
and `sweep-*`. The plant-built plain pinned binary is started under
`setarch -R` (ASLR off) at a loopback port with the exact invocation
`--once --debug=remote 127.0.0.1:PORT /bin/true`; no debugger is present.
Under that invocation, shell and parent environment `src=xmalloc(2)` is
at `0x55555561c410` and the adjacent live `tdesc_feature` is at
`0x55555561c430`. A gdb-under-`setarch -R` measurement put the object at
`0x...c470` instead, so gdb's inferior environment shifts the heap by
0x40. Witness W139 measured the same pinned binary at `0x...c460` from a
bash parent and `0x...c420` from a Python parent, a 0x30 shift from the
parent environment alone. Addresses must be re-derived in the exact
target configuration; `0x...c430` is not portable across builds or
parent environments.

The 64-byte `SLEN=1` payload keeps the next chunk size at `0x61`, sets
the object vptr to `obj+8 = 0x55555561c438`, and puts `abort@plt`
(`0x555555561f70`) in fake slot `+0x10`. Server: `OK` to `QTDPsrc`,
`E01` to `qGetTLSAddr`, then SIGABRT (`SERVER_RC=134`). Short N=8 and
well-formed N=16 exit 0. Two consecutive runs: 3 PASS / 0 FAIL each.
An address sweep over candidate objects `0x...c430`..`0x...c4a0` in 0x10
steps produced 134 only at `0x...c430`, 139 at all seven others; the
successful address is measured, not a lucky guess. This removes the
debugger condition from the chosen-function marker; `abort()` is a
marker, not a command, so the grade is unchanged.

Rung-5 negatives, all preserved. `readelf -n` reports CET `IBT, SHSTK`;
the plain binary is PIE. Undefined symbols contain no `system`,
`popen` or `execve`; the only command primitive is `execvp`, invoked
once at `0x52a04` inside `fork_inferior` with a multi-argument setup.
The corrupted vcall is `0x2d4bf call rax` with `%rdi = %rbx = object`,
so file and argv alias one pointer and no argv is set up. Disassembly
of the whole `.text` yields no `mov rsp,rdi/rbx`, `xchg rsp,*` or
`pop rsp; ret`; only `pop rdi/rsi/rdx; ret` and `leave; ret` exist.
Forged slot retargets under the same wire-only ASLR-off setup:
`_exit@plt` (`0x555555564640`) and a bare `ret` (`0x55555557d4de`)
gave SIGILL (132), `exit@plt` (`0x555555564380`) and `getpid@plt`
(`0x555555564540`) gave SIGSEGV (139). No clean distinctive exit,
no command, no side effect. `qGetTLSAddr` is `E01` in every case.

Diagnostic on the bare-`ret` retarget, kept as an UNKNOWN rather than a
CET claim: under gdb with `setarch -R` (object `0x...c470` in that
configuration, payload vptr `0x...c478`), SIGILL landed at
`rip=0x55555557d4df` with `rax=0x55555557d4de`. The target bytes are
`c3 90` (`ret`, `nop`) at `0x2d4de/0x2d4df`, so the `ret` appears to have
executed and the fault was reported one byte later; IBT-on-indirect-call
is therefore NOT established as the cause. Shadow-stack enforcement or
subsequent corrupted control flow remain untested explanations. This
does not change the observation that no retarget produced a command.

Witness W139 (tape #2134) rebuilt the same pin from a clean git archive of
`2411b93` and replayed W4: ESTABLISHED at the labeled scope, no rung 5.
My exact wire bytes SIGSEGVed on its binary; sweeping objects with its
committed client from a bash parent gave 134 only at `0x...c460`, while a
Python parent put the object at `0x...c420`. Changing only the vptr field
to `obj+8 = 0x...c468` (`68c4615555550000`) gave two 3 PASS / 0 FAIL
runs with client transcripts byte-identical to canonical. W139 verified
the rung-5 negatives on its own binary (CET IBT,SHSTK; only `execvp` at
`0x52a04`; `call *%rax` at `0x2d4bf` with `rdi=rbx`; `c3 90` at
`0x2d4de/0x2d4df`) and left the bare-`ret` SIGILL cause UNKNOWN. No grade
change; the environment-sensitivity NIT is folded into this section and
the status report.

## Wire-only rung 5: libc system() through the forged slot (W5, 2026-11-23T03:35Z)

The W4 "no command function" negative was about imported symbols. The
plain build imports no `system`, `popen`, `execve` or `posix_spawn`, only
two-argument `execvp`; all 195 `.plt.sec` stubs do begin with `endbr64`,
so CET IBT does not block a PLT-style indirect call. Under `setarch -R`
the loader addresses are fixed: `ldd` reports libc at
`0x00007ffff7800000`, `nm -D` places `system` at offset `0x58750`
(`0x7ffff7858750`), and the entry instruction is `endbr64`. Calling that
address directly — not through an import — removes the marker limitation
of W2/W4.

`rsp/r5_system_verify.sh` first DERIVES the adjacent object address:
candidates `0x...c400`..`0x...c4c0` are tried in 0x10 steps with
`abort@plt` in the forged slot; the one returning 134 is taken (here
`0x...c430`, vptr `0x...c438`). This is the concrete repair for W139's
environment-sensitivity NIT: no address is trusted from an earlier run.
`PATH` is then replaced with a string of exactly the original length,
starting at `rsp/r5-bin/`, so the total environment size is unchanged.
The harness writes an executable whose six-byte name is the little-endian
vptr bytes up to the first NUL (`38 c4 61 55 55 55`, displayed as
`8\304aUUU` by `ls -b`). `system("8\xc4aUUU")` reaches `/bin/sh`, which
resolves that name in the lab PATH directory and writes
`R5_SYSTEM_MARKER=1` to `r5-bin/marker`.

The 64 decoded bytes are the W4 payload with the slot changed:
0..23 `0x41` filler, 24..31 preserved next-chunk size `0x61`, 32..39
vptr `obj+8` = `38c4615555550000`, 40..55 `0x42`, 56..63 `system`
little-endian `508785f7ff7f0000`. Wire replies are `OK` to `QTDPsrc` and
`E01` to `qGetTLSAddr`; the server then exits 0 because `system()`
returns and the destructor continues. Four cases, repeated with the
previous fixed-address harness and with the final deriving harness:
vulnerable+system rc 0 / `MARKER=1` with file content
`R5_SYSTEM_MARKER=1`; vulnerable+`abort@plt` rc 134 / no marker; fixed
build+system `E01` / rc 0 / no marker; vulnerable+well-formed `SLEN=16`
rc 0 / no marker. Normalized hash of the four client transcripts and
four marker records:
`9104b0ec51a09c94922438a62d9df2bfa108f4b4e6f8e7f18abc26d3f4886a98`.
Evidence: `rsp/evidence/r5-system-*.{log,client.out,marker}`, including
the sweep logs that show 139 at c400/c410/c420 and 134 at c430.

A separate negative from this wake: running the server under `env -i`
and sweeping objects `0x...c400`..`0x...c4b0` with the abort slot gave
SIGSEGV (139) at every candidate, so a bare minimal environment is not a
portable replay condition; the address must be derived in the exact
target configuration. The forged call site remains `0x2d4bf call rax`
with `rdi=rbx=object`, `rdx` a constant and `rsi` clobbered by the
preceding `operator delete`; no argv setup exists, which is why the
command string is constrained to the vptr bytes rather than freely
chosen. That constraint is part of the demonstrated condition: the
command is pre-staged by the lab under a name forced by the heap address.

Grade: rung 5 demonstrated locally under the recorded conditions —
ASLR off, exact build, measured libc/heap addresses, same-length PATH,
pre-staged command. No debugger, no in-process marker function, no
forced execution. Independent witness replay is still required for
ESTABLISHED; W4's rung-4 ESTABLISHED verdict is unchanged by this result.

