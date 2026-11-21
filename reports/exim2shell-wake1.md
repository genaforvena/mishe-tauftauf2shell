# exim2shell — first wake: ASan builds and loopback traffic, no sanitizer report

Status: **RUNG 0 still**. No crash, no ASan WRITE, no memory-corruption
observation. This report records the build recipe and the negative result so a
fresh wake does not repeat the setup blindly.

## Pins and builds (2026-11-21 20:14Z)

`cd lab/frontier/exim2shell/src && sha256sum -c SHA256SUMS` → 2/2 OK, matching
the charter digests. Both release trees were already extracted; both were built
in place with `USE_GNUTLS=yes`, `USE_GNUTLS_PC=gnutls`,
`AVOID_GNUTLS_PKCS11=yes`, `CFLAGS += -O1 -g -fno-omit-frame-pointer
-fsanitize=address -fno-stack-protector`, `EXTRALIBS_EXIM += -fsanitize=address`,
`LFLAGS += -fsanitize=address` and the default router/transport/lookup set from
`src/EDITME` (a minimal Local/Makefile without TRANSPORT_SMTP fails to link).

Build prerequisites found on this host: `libdb-dev` was absent (installed with
`sudo apt-get install -y libdb-dev`, provisioning only); Exim's `macro_predef`
helper links with `LFLAGS` only, so ASan must be added there as well as to
`EXTRALIBS_EXIM`.

Resulting binaries:
`src/exim-4.99.2/build-Linux-x86_64/exim` and
`src/exim-4.99.3/build-Linux-x86_64/exim`, 9.5M each. `ldd` shows
`libasan.so.8` and `libgnutls.so.30`; `-bV` shows GnuTLS and the expected
routers/transports. Configs are `build-4.99.{2,3}/configure`, root-owned 0644
(Exim refuses a config not owned by root when CONFIGURE_OWNER is unset),
`local_interfaces = 127.0.0.1`, ports 25252 (vulnerable) and 25253 (fixed).
Self-signed cert/key under `certs/`.

## Traffic actually driven

Harness: `lab/frontier/exim2shell/trigger.py` (loopback only). Sequence per
connection: `EHLO` → `STARTTLS` (TLS 1.3, `TLS_AES_256_GCM_SHA384`) → `EHLO` →
`MAIL FROM` → `RCPT TO` → `BDAT <n>` with one body byte inside TLS → client
`close_notify` → cleartext bytes. Python `ssl.unwrap()` blocks because 4.99.2
calls `tls_close(NULL, TLS_NO_SHUTDOWN)`; the harness catches the timeout and
reuses the detached fd, which is still on the wire after the client alert.

Four cleartext variants were run against 4.99.2:

1. `ungetc`: `BDAT 5`, 4 filler bytes + CRLF header + bare-LF header —
   server logged "lost while reading message data (header)".
2. `two`: `BDAT 2 LAST`, remaining byte followed by commands — message was
   accepted (`250 OK id=...`), but pipelined commands tripped a sync error.
3. `three`: `BDAT 2 LAST`, chunk completed, `RSET`/`MAIL`/`RCPT`/`DATA` accepted
   stepwise, three-header DATA message completed with `.` — no report.
4. `four`: `BDAT 100` still active, cleartext `A: 1\r\nB: 2\n` (bare LF) —
   no report.

Logs: `build-4.99.2/trigger-*.log`, `build-4.99.2/log/mainlog`,
`build-4.99.2/asan.*` (none created). ASan is genuinely linked into the live
daemon (`grep -c libasan /proc/<pid>/maps` → 5).

## What this does and does not establish

Established: the pinned 4.99.2 tree builds with GnuTLS + ASan; a loopback
client can reach STARTTLS, a mid-BDAT TLS close_notify and cleartext continuation
with the vulnerable daemon accepting the rest of the session.

Not established: any out-of-bounds or use-after-free access. In particular
`tls_ungetc` was not observed to execute against the freed `xfer_buffer`. The
receive-function layering makes the path subtle: `tls_close()` replaces the
top-level `receive_*` pointers with cleartext ones while the bdat layer retains
`lwr_receive_ungetc = tls_ungetc`; which pointer a header parser actually calls
depends on when `bdat_pop_receive_functions()` runs. No rung 2/3/4 is claimed.

## Next wake (bounded)

Determine whether `tls_ungetc` is reached at all: add a lab-only instrumented
build (or gdb breakpoint on `tls_ungetc` in the SMTP child) that prints
`state_server.xfer_buffer_lwm` and `xfer_buffer` at entry after close_notify.
If it is not reached, find the receive-pointer transition that restores it; if
it is reached, capture the ASan WRITE offset and replay the identical bytes
against 4.99.3 on port 25253. Preserve the negative results above.

Replay commands:

```
cd lab/frontier/exim2shell
src/exim-4.99.2/build-Linux-x86_64/exim -bd -oX 25252 -d-all   # 4.99.2
src/exim-4.99.3/build-Linux-x86_64/exim -bd -oX 25253 -d-all   # 4.99.3 control
python3 trigger.py 25252 ungetc     # also: two, three, four
python3 trigger.py 25253 ungetc     # fixed control, identical bytes
```

The lab config must be root-owned 0644 (Exim's ownership check). Listener is
bound to 127.0.0.1 only. No rung-5 claim is in scope.
