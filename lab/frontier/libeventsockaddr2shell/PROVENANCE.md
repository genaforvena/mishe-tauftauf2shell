# PROVENANCE — libeventsockaddr2shell (CVE-2026-63388)

## Claim source and pins

- Advisory: https://github.com/libevent/libevent/security/advisories/GHSA-cvq5-vrvr-j338
  (published 2026-07-01, High 8.4, CWE-787/CWE-617). It embeds a complete
  server/client PoC, ASan trace, gdb controlled-pointer trace and production
  crash recipe. Claim source is a claim; everything below was observed locally.
- CVE-2026-63388. Affected `<= 2.1.12` and `<= 2.2.1-alpha`; patched `2.1.13`
  and `2.2.2-alpha`. PoC pins vulnerable master commit
  `1b7cc9b58d6a5fdd5f33a43168245c2e1f35291f`.
- Fix commit `52057cb33d0c20c0a0453fbabe6c0c96854931b9`, parent
  `9877a7205ea0`, 3 files +21/-11. It makes the length check unconditional,
  changes `conn_address` from a 28-byte union to `struct sockaddr_storage`,
  propagates the failure in `http.c`, and widens the return to `int`.
- Acquired 2026-11-27 with
  `curl -fsSL https://codeload.github.com/libevent/libevent/tar.gz/<commit>`
  and the `.patch` URL for the fix. No external probing; all runtime targets
  are AF_UNIX sockets or 127.0.0.1 started by this harness.

## Pin hashes (sha256)

- `pins/libevent-vuln-1b7cc9b5.tar.gz`
  `86dde8dfe1e2f60f954547e5f48cc3bd2570f051bcf4403a8c96f5ee45c92b71`
- `pins/libevent-fixed-52057cb3.tar.gz`
  `718ea8883dec950adde4449c0419613f0b0a9346c1b3e1adfa5c73d6a5ec3bd0`
- `pins/fix-52057cb3.patch`
  `643fe7edfdbeac3009722599cc36d079eb72698e14f71e36b42d7a99a8396d62`

## Source-bound mechanism (pinned bytes)

Vulnerable `src-vuln/bufferevent_sock.c:119-126`:

```c
EVUTIL_ASSERT(addrlen <= sizeof(bev_p->conn_address));
memcpy(&bev_p->conn_address, addr, addrlen);
```

`EVUTIL_ASSERT` compiles out under `NDEBUG`. `conn_address` is a 28-byte
union followed by `dns_request` in `bufferevent-internal.h`. A call from
`http.c:4686` in `evhttp_get_request_connection()` passes the `socklen`
returned by `accept4` in `listener.c:447`; an AF_UNIX abstract name makes the
kernel report `peer_socklen=110` and supply 110 attacker-influenced bytes.
The 110-byte `memcpy` overwrites 8 bytes of `dns_request` and 74 bytes of the
following heap chunk (the input `evbuffer`), including its `lock` pointer.

## Observed locally (2026-11-27, gcc 13.3, gdb, x86_64)

Commands: `bash bootstrap.sh`, `bash run-all.sh`, `bash run-probe.sh`.

- `bash run-all.sh`: rc 0, **23 PASS / 0 FAIL**.
- GCC ASan on vulnerable commit: `AddressSanitizer: heap-buffer-overflow`,
  `WRITE of size 110`, frame `evhttp_get_request_connection ...
  src-vuln/http.c:4686`, `0 bytes after 520-byte region` allocated by
  `bufferevent_socket_new ... bufferevent_sock.c:357`. Raw:
  `evidence/asan-vuln-attack.log`.
- Loopback-TCP control on the same vulnerable build (16-byte `sockaddr_in`):
  no ASan report, server alive. Raw: `evidence/asan-vuln-tcp.log`.
- Fixed commit ASan attack: no ASan report, server alive. Raw:
  `evidence/asan-fixed-attack.log`.
- Production build: vulnerable server SIGSEGV (core dumped) after the crafted
  connect; fixed server alive. Raw: `evidence/prod-vuln-attack.log`,
  `evidence/prod-fixed-attack.log`.
- `bash run-probe.sh`: **16 PASS / 0 FAIL**. Three attacker-chosen 48-bit
  values `0x1234567890AB`, `0xDEADBEEF1337`, `0xCAFEBABE9988` each appear as
  `mutex=<chosen>` in libc `___pthread_mutex_lock`, in `rdi`, with a SIGSEGV,
  an `evbuffer_get_length` frame (`src-vuln/buffer.c:640`) and
  `peer_socklen=110` from `accept_socket_cb`. Raw: `evidence/gdb-*.log`.
- Client writes only 6 bytes (lower 48 bits) at `sun_path[102..107]`; the
  advisory's 8-byte example is clamped by the 108-byte `sun_path` array.

## Negative results and corrections preserved

- A one-byte abstract-name control also produces the same ASan WRITE-110 on
  this host: Linux reports `socklen=110` for the AF_UNIX accept regardless of
  the abstract name length. The short-name control is therefore NOT a safe
  input; the loopback-TCP control is the safe input.
- The advisory's gdb `si_addr = mutex+0x18` was NOT reproduced: in batch mode
  `$_siginfo._sifields._sigfault.si_addr` printed `0x0`. The chosen pointer in
  `mutex=`/`rdi` and the faulting call were reproduced; the exact fault address
  remains UNKNOWN here.
- The advisory's line numbers (`bufferevent_sock.c:119-126`, `http.c:4686`)
  match the pinned vulnerable commit. Its `Version` details were Docker-based;
  this harness builds directly on the host without Docker.
- No benign marker execution, command, wire-to-TCP path, or ASLR-defeating
  groom was demonstrated. The CVSS attack vector is Local (AF_UNIX peer).
- Replay hashes are recorded in `reports/libeventsockaddr2shell-status.md`
  after the clean `git archive` check.
