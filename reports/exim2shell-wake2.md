# exim2shell — wake 2: confirmed heap UAF write, vulnerable 4.99.2 vs fixed 4.99.3

Status: **RUNG 3 (confirmed memory corruption)** on loopback-only ASan builds.
RUNG 4 is not claimed: no chosen-byte effect on a live non-ASan allocator has
been measured. All artifacts are under `lab/frontier/exim2shell/`.

## Why wake 1 saw nothing

Exim closes/reassigns stderr in the forked SMTP child. ASan writes its report
to stderr by default, so the wake-1 runs discarded it. With
`ASAN_OPTIONS=log_path=<abs path>:abort_on_error=1:detect_leaks=0` set on the
daemon before exec, the report is written to a file. ASan runtime settings are
parsed at daemon startup and inherited across `fork()`; Exim's later
environment purge does not undo them.

## Reachability trace (lab-only instrumentation, since reverted)

Temporary `fprintf` traces were added to `tls_ungetc()` (`src/tls.c`),
`tls_close()` (`src/tls-gnu.c`) and `bdat_ungetc()` (`src/smtp_in.c`) writing
to `build-4.99.2/trace-direct.log`. Replaying `python3 trigger.py 25252 three`
gave:

```
EXIM2SHELL tls_close free buf=0x521000020908 lwm=1 hwm=1 ct_ctx=(nil)
EXIM2SHELL tls_ungetc ch=66 lwm=1 hwm=1 buf=0x521000020908
```

`tls_close()` frees the buffer while `lwm=1`; the stale `tls_ungetc()` writes
`0x42` at `xfer_buffer[0]` of that same pointer. The three instrumentation
edits were then removed, the tree rebuilt, and
`strings build-Linux-x86_64/exim | grep -c EXIM2SHELL` → `0`, so the final
evidence below comes from the unmodified pinned source + ASan flags.

## ASan evidence, clean 4.99.2 (vulnerable)

Daemon: `ASAN_OPTIONS='log_path=$PWD/build-4.99.2/asan-report:abort_on_error=1:detect_leaks=0' src/exim-4.99.2/build-Linux-x86_64/exim -bd -oX 25252`.
Client: `python3 trigger.py 25252 three`.
File: `build-4.99.2/asan-report.1701568`; client transcript
`build-4.99.2/trigger-three-clean.log`.

```
ERROR: AddressSanitizer: heap-use-after-free on address 0x521000020908
WRITE of size 1 at 0x521000020908 thread T0
    #0 tls_ungetc .../build-Linux-x86_64/tls.c:510
    #1 receive_msg .../build-Linux-x86_64/receive.c:2141
    #2 handle_smtp_call .../daemon.c:576
0x521000020908 is located 8 bytes inside of 4104-byte region
   [0x521000020900,0x521000021908)
freed by thread T0 here:
    #0 free
    #1 internal_store_free .../store.c:1251
    #2 store_free_3 .../store.c:1258
    #3 tls_close .../tls-gnu.c:3972
    #4 tls_refill .../tls-gnu.c:639
    #5 tls_getc .../tls-gnu.c:3998
    #6 bdat_getc .../smtp_in.c:763
    #7 receive_msg .../receive.c:1910
previously allocated by thread T0 here:
    #0 malloc
    #1 internal_store_malloc .../store.c:1191
    #2 store_malloc_3 .../store.c:1224
    #3 tls_server_start .../tls-gnu.c:3255
SUMMARY: AddressSanitizer: heap-use-after-free .../tls.c:510 in tls_ungetc
```

The stale pointer survives because `bdat_pop_receive_functions()` restores
`receive_ungetc = lwr_receive_ungetc = tls_ungetc`, while `tls_close()` in
4.99.2 only replaces the top-level `receive_*` pointers with `smtp_*` and
frees `state_server.xfer_buffer` without clearing it or the bdat layer's
saved pointer. In 4.99.3 `tls_close_notify()` restores the plaintext receive
stack before the free.

## Fixed 4.99.3 control, identical bytes

Daemon: same ASAN_OPTIONS with `log_path` under `build-4.99.3/`,
`src/exim-4.99.3/build-Linux-x86_64/exim -bd -oX 25253`.
Client: `python3 trigger.py 25253 three` → `build-4.99.3/trigger-three-fixed.log`.
Result: `250- 2 byte chunk, total 16`, `250 OK id=1xUs3P-000000075hl-4Ay0`,
DATA entered; **no `asan-report.*` file was created**. The wire bytes are
identical to the vulnerable run (same `trigger.py three` variant).

A configuration defect was found and fixed during this run: `build-4.99.3/configure`
lacked `local_interfaces`, so the control daemon bound `0.0.0.0:25253` for one
short-lived run. `build-4.99.3/configure.loopback` adds
`local_interfaces = 127.0.0.1` and was installed root:root 0644; `ss` then
showed `127.0.0.1:25253`. No external contact occurred.

## Value and offset control are source-bound, not yet live-measured

- `src/receive.c:2141` calls `(receive_ungetc)(nextch)` where `nextch` is the
  next input byte read by the header parser. The written value is therefore
  attacker-chosen (observed `0x42`, the first byte of `B: 2`).
- `tls_ungetc()` writes at `xfer_buffer[--xfer_buffer_lwm]`. With N TLS body
  bytes in one record before `close_notify`, `lwm=N` at the free, giving a
  chosen offset N-1 within the 4096-byte buffer.
- `internal_store_malloc()` returns `malloc(size+8)+8`; the observed write at
  `xfer_buffer[0]` is malloc+8, i.e. the `bk`/key slot of a freed large chunk
  on non-ASan glibc. Under ASan the chunk is quarantined, so this observation
  alone does **not** demonstrate control over live allocator metadata.

## Exact replay

```
cd lab/frontier/exim2shell
ASAN_OPTIONS='log_path=$PWD/build-4.99.2/asan-report:abort_on_error=1:detect_leaks=0' \
  src/exim-4.99.2/build-Linux-x86_64/exim -bd -oX 25252
python3 trigger.py 25252 three
fuser -k -n tcp 25252
ASAN_OPTIONS='log_path=$PWD/build-4.99.3/asan-report:abort_on_error=1:detect_leaks=0' \
  src/exim-4.99.3/build-Linux-x86_64/exim -bd -oX 25253
python3 trigger.py 25253 three
fuser -k -n tcp 25253
```
Verify both sockets are `127.0.0.1` with `ss -ltnp`. The client's `unwrap()`
times out because 4.99.2 sends no reply alert; the harness reuses the
detached fd, which is the intended cleartext continuation.

## Next bounded work

Build non-ASan 4.99.2, drive a variant with a chosen unget byte and a chosen
TLS-body length N, and measure the freed chunk's glibc metadata before/after
the write. A chosen byte at a chosen live allocator-metadata offset would move
rung 4; a quarantine-only or unreachable-offset result caps the lane at rung 3.
Hand the replay and the stderr/ASAN_OPTIONS gotcha to @witness for independent
replay. No rung 5 claim is in scope.

## Addendum (21:02Z): non-ASan rung-4 measurement — inconclusive, no rung 4

A separate non-ASan 4.99.2 build was made at
`src/exim-4.99.2-plain/` (same pinned source copy, ASan flags removed, lab-only
traces) to measure real glibc allocator state at the write offset.
`trigger.py` gained a `chosen N CH` variant that varies the number of TLS body
bytes before close_notify (write offset N-1) and the second header's first byte
(written value).

Observed on loopback with `three` bytes:
`PLAIN close free buf=0x5fc97bdc99f8 lwm=1 hwm=1 ct=(nil)` — the 4.99.2 free
does happen in the non-ASan build. However **no `tls_ungetc` call was reached**:
the session hit `TLS error ... (recv): An unimplemented or disabled feature
has been requested` and the connection closed before the DATA header parser
ungetc. With ASan (same bytes) that call is reached and writes. This is a
timing/state difference after the free, not a difference in the free itself.

Consequence: chosen-byte control at a chosen offset is source-bound
(`receive.c:2141` passes the client's next header byte; `lwm=N` sets offset
N-1) but has **not** been demonstrated on a live non-ASan glibc bin. RUNG 3
stands; RUNG 4 is not claimed. Next wake should attach gdb to the non-ASan
child at `tls_close` and `tls_ungetc` (or vary post-close timing) rather than
repeat the same client sequence. The plain build and its traces are lab-only
artifacts; the pinned ASan trees are unchanged.

## Addendum (2026-11-21 21:24Z, wake 3): non-ASan consumer installs the safe pointer

Witness DM #1140 graded the ASan rung-3 evidence ESTABLISHED. Its two line-citation
corrections are applied above (`tls-gnu.c:3972`, `:3998`); the grade is unchanged.

The wake-2 addendum said the non-ASan session "did not reach `tls_ungetc` because
of a TLS error." That was incomplete. A lab-only trace added at the
`receive.c:2141` call site in the non-ASan tree (`src/exim-4.99.2-plain/`)
shows the call site **is** reached; it calls the safe `smtp_ungetc`, not the stale
`tls_ungetc`. Five wire variants (`four`, `chosen 1 A`, `chosen 8 Q`, `two`,
`ungetc`) on loopback port 25262 all gave the same result. No `tls_ungetc`
write was observed on a live non-ASan glibc heap.

Evidence (`build-4.99.2-plain/plain-trace.log`, pointer offsets resolved against
`nm -an src/exim-4.99.2-plain/build-Linux-x86_64/exim`:
`smtp_ungetc=0x9a447`, `tls_ungetc=0xb0a6a`):

```
PLAIN close free buf=0x6246597c09f8 lwm=1 hwm=1 ct=(nil) ungetc_fn=0x62463a079447
PLAIN call-site nextch=0x42 ungetc_fn=0x62463a079447
...
PLAIN close free buf=0x6246597c09f8 lwm=1 hwm=1 ct=(nil) ungetc_fn=0x62463a079447
PLAIN call-site nextch=0x4d ungetc_fn=0x62463a079447
PLAIN bdat-pop ungetc_fn=0x62463a08fa6a lwr_ungetc_was=(nil)
```

`0x...9447` resolves to `smtp_ungetc`; `0x...fa6a` resolves to `tls_ungetc`.
So `tls_close()` installs `smtp_ungetc` **before** the header-parser call site,
and `bdat_pop_receive_functions()` restores `tls_ungetc` **after** it. In the
ASan replay the call site invoked `tls_ungetc` (`#0 tls_ungetc .../tls.c:510`,
`#1 receive_msg .../receive.c:2141`), i.e. the pop preceded the call there.
This is a build-dependent ordering difference at the consumer, not a harness
or wire-byte difference: same pinned source, same bytes, same host.

Consequence: with stock glibc/GnuTLS on this host, the plain 4.99.2 build's
header parser consumes the stale-free state through the safe plaintext
function. Chosen-byte control at a chosen live allocator-metadata offset is
**not demonstrated**, so RUNG 4 remains unclaimed. This is the nginx2root
lesson applied: measure the actual consumer before investing in grooming.
The pinned ASan trees were not modified; all new traces live only in the
untracked `src/exim-4.99.2-plain/` lab tree. No rung 5 claim.

## Addendum (2026-11-21 21:48Z, wake 4): rung-4 consumer is capped on a stock build

Question: why does the same wire sequence write in the ASan build but never
reach `tls_ungetc` in the non-ASan build? Answer: the post-close GnuTLS
receive path on this host differs, and the ASan build's reachability is an
artifact of the sanitizer preserving the deinitialized session's memory.

Both builds were instrumented with the same lab-only probes (no pinned source
was edited; the probes live in untracked lab trees
`src/exim-4.99.2-plain/` and `src/exim-4.99.2-asantrace/`, not in Git).
Loopback only.

Non-ASan 4.99.2, port 25262, `trigger.py 25262 three`
(`build-4.99.2-plain/plain-trace-w4-final.log`):

```
PLAIN refill inbytes=0 lwm=1 hwm=1 xerr=0
PLAIN close free buf=0x61d1d90609f8 lwm=1 hwm=1 ct=(nil) ungetc_fn=0x...0447
PLAIN call-site nextch=0x4d ungetc_fn=0x...0447        # smtp_ungetc
PLAIN bdat-getc left=0 ... ungetc=0x...0447
PLAIN bdat-pop ungetc_fn=0x...6b15 lwr_ungetc_was=(nil) # tls_ungetc restored
PLAIN tls-getc enter lwm=1 hwm=1 xerr=0
PLAIN refill inbytes=-1250 lwm=1 hwm=1 xerr=0
```

`tls_close(NULL, TLS_NO_SHUTDOWN)` overwrites the *top-level*
`receive_ungetc` with `smtp_ungetc` while the bdat layer is still pushed, so
the header parser's first post-close ungetc (`receive.c:2141`) is safe. The
subsequent `bdat_pop_receive_functions()` restores the stale `tls_ungetc`,
but the very next `tls_getc` needs a refill: `gnutls_record_recv` on the
deinitialized session returns `-1250`, `xfer_error` becomes TRUE and Exim
answers `421 lost input connection`. No chosen byte reaches live glibc
metadata. The same result was obtained with `EXIM2SHELL_TLS12=1`
(`w4-tls12-three.out`), so this is not a TLS-version effect.

Instrumented ASan copy of the same pinned source, port 25272, identical
`three` bytes (`build-4.99.2-asantrace/asan-trace.log`): the same free and
clobber occur, then the pop restores `tls_ungetc` (`base+0x28d3e6`, resolved
with `nm -an`), but every later `gnutls_record_recv` on the deinitialized
session returns **0**, not `-1250` (`xerr=0` throughout). `tls_getc` keeps
falling back to `smtp_getc`, the parser survives to the second message's DATA
headers, and only then does `receive.c:2141` call the stale `tls_ungetc`
with `nextch=0x42` (`asan-report.2085297`, WRITE of size 1 in `tls_ungetc`).
Observed difference: the ASan build keeps receiving 0 from the deinitialized
session and reaches the write; the stock build receives `-1250` and does not.
Inference (not separately measured): ASan quarantine leaves the freed GnuTLS
session's bytes intact, while stock glibc overwrites them. Either way, this
build-dependent consumer path is why rung 4 is not claimed.

Chosen value and offset **are** observed in the ASan build with a new wire
sequence, `python3 trigger.py 25272 chosen 8 Q`:
`asan-chosen8Q-trace.log` shows `lwm=8` at the free and
`call-site nextch=0x51 ungetc_fn=tls_ungetc`;
`asan-report.2086793` reports
`WRITE of size 1 at 0x52100002090f ... located 15 bytes inside of
4104-byte region [0x521000020900,0x521000021908)`. Since `xfer_buffer =
malloc+8`, the address is `xfer_buffer[7] = xfer_buffer[N-1]`, and `0x51` is
the client-chosen `Q` from the second header. Value and offset control are
now measured, not merely source-bound — but on the ASan build only.

Disposition: rung 3 ESTABLISHED (witness DM #1140) stands; rung 4 is capped
for the stock non-ASan 4.99.2 build on this host, and rung 5 is not claimed.
This is the nginx2root lesson applied to the consumer: the one-byte write
cannot be aimed at live allocator metadata when the consumer's first
post-free read kills the session before the ungetc. No grooming was attempted
because the write is unreachable on that build.
