# Real c-icap build — W1 (2026-11-24 18:3xZ)

Provisioning only: both tarballs came from codeload GitHub tags; no probe or
traffic off loopback. Exact source hashes verified against the pinned harness
copies: the four `C_ICAP_0.6.5` files in `../pinned/` match the release
tarball byte-for-byte (sha256 `b4988efe…37ad`, `fa3fe4ef…b39219a`,
`e953e2f6…1e4619`, `760e573b…4e13fb3`). Release tarball sha256
`6ac51b6dd39690a6ccc62e807f065e92131498687d4201a69ae9570b68bab1e5`.

```
curl -sSL -o C_ICAP_0.6.5.tar.gz \
  https://codeload.github.com/c-icap/c-icap-server/tar.gz/refs/tags/C_ICAP_0.6.5
tar xzf C_ICAP_0.6.5.tar.gz
cd c-icap-server-C_ICAP_0.6.5 && autoreconf -i
mkdir ../build-asan && cd ../build-asan
CFLAGS='-O0 -g -fsanitize=address -fno-omit-frame-pointer' \
LDFLAGS='-fsanitize=address' ../c-icap-server-C_ICAP_0.6.5/configure
make -j4
gcc -std=gnu11 -O0 -g -fsanitize=address -fno-omit-frame-pointer \
  -I ../c-icap-server-C_ICAP_0.6.5/include -I include \
  real_api_harness.c -o real_api_harness \
  -L .libs -licapapi -Wl,-rpath,$PWD/.libs
./real_api_harness attack 90
./real_api_harness safe x
```

Fixed control: GitHub has **no `C_ICAP_0.6.6` tag** (latest tag is 0.6.5).
Apply `../pinned/fix.patch` (`05dcead`) to a copy of the 0.6.5 tree; hunk 2
(teardown loop) fails to apply verbatim because of surrounding drift, so apply
its exact change (`i < 5` bound, NULL-out) by hand, then rebuild with the same
flags. No released 0.6.6 binary was built; this is a patch-derived control.

Observed (raw outputs in `../evidence/real-*.out`, gitignored):

- vuln ASan, sixth value `90`, `72`, `4242`: each prints
  `parse=0 entities5=<addr> trash0=<same addr> alias=1 trash0_type=2
  trash0_start=<value>`, then ASan `heap-use-after-free`, `READ of size 4`,
  `destroy_encaps_entity header.c:631` from `ci_request_destroy
  request_common.c:417`, freed at `header.c:635` from `:413`, allocated at
  `header.c:616` from `ci_request_alloc_entity request_common.c:200`; rc 1.
- vuln ASan, four-entity safe: `entities5=(nil) trash0=(nil) alias=0`,
  `destroy done`, rc 0, no sanitizer report.
- upstream-patched fixed ASan, attack `90` and safe: `entities5=(nil)`,
  `alias=0`, `destroy done`, rc 0, no sanitizer report.

Scope limit: the header string is passed directly to the exported
`process_encapsulated()` on a real `ci_request_t`; this is NOT a socket, not
`parse_header()`/`process_request()`, and not a running `icap-server`. No
pointer/IP/command control and no r5.

## W2 — socket-fed header bytes (2026-11-24 18:4xZ)

`wire_api_harness.c` writes a complete `REQMOD ... ICAP/1.0` request (request
line, `Host`, six-entity `Encapsulated:`, blank line) into an `AF_UNIX`
socketpair, reads it back with the library's exported
`ci_connection_read_nonblock()`, calls exported `ci_headers_unpack()` and then
the exported `process_encapsulated()` on each `Encapsulated:` header, then
`ci_request_destroy()`. The library's `ci_read_icap_header()` is not exported
and `ci_wait_for_data()` rejects this synthetic fd, so those two calls are
bypassed; the post-read loop follows `request.c:519-529` in shape.

Observed (raw outputs `../evidence/real-wire-*.out`):

- Vuln ASan, sixth value 90 and 4242: `wire_bytes=155/157 unpack=0 headers=4`,
  `alias=1 trash0_type=2 trash0_start=<value>`, ASan `heap-use-after-free`
  `READ of size 4` at `header.c:631` from `ci_request_destroy`; rc 1.
- Vuln ASan four-entity safe: `alias=0`, `destroy done`, rc 0.
- Upstream-patched fixed ASan, attack 90 and safe: `alias=0`, rc 0, clean.

Scope: a local socketpair, not a network socket; no `parse_request()` /
`process_request()` and no running `icap-server`. No wire reach off loopback,
no pointer/IP/command control, no r5.

## W3 — real server on loopback (19:0xZ)

`live/run.sh` starts the real ASan `c-icap` binary from either build tree
on 127.0.0.1, sends one crafted request with `live/client.py`, stops the
server and reports `ASAN=YES|NO`. Six-entity REQMOD (90/4242) and six-entity
OPTIONS with `Connection: close` (4242) both drive the full
`parse_header()`/`process_request()` path and end in the `header.c:631`
UAF at teardown; safe, valid one-entity and patch-derived fixed controls
are clean. Full commands, the keepalive negative and the live-server
ceiling are in `live/README.md`; raw output in `../evidence/live-*.out`.

## W6 — plain-build consumer probe (22:2xZ)

Rebuild the same pinned tree with no sanitizer and link the existing API
harness against it:

```
mkdir -p /tmp/cicap-real/build-plain && cd /tmp/cicap-real/build-plain
CFLAGS='-O0 -g -fno-omit-frame-pointer' \
  ../c-icap-server-C_ICAP_0.6.5/configure && make -j4
gcc -std=gnu11 -O0 -g -fno-omit-frame-pointer \
  -I ../c-icap-server-C_ICAP_0.6.5/include -I include \
  <repo>/lab/frontier/cicap2shell/realbuild/real_api_harness.c \
  -o real_api_plain -L .libs -licapapi -Wl,-rpath,$PWD/.libs
gdb -q -batch -x <repo>/lab/frontier/cicap2shell/realbuild/consumer_probe.gdb \
  --args ./real_api_plain attack 90
gdb -q -batch -x <repo>/lab/frontier/cicap2shell/realbuild/malloc_window.gdb \
  --args ./real_api_plain attack 90
```

Call 6 prints the chosen `start` with `entity=(nil)`; call 7 prints
`type=21840 start=42031 entity=<varying pointer>` for wire values 90, 72
and 4242 alike, then SIGSEGVs in `__GI___libc_free` at `header.c:634`.
No `malloc` appears between the two calls. Plain `./real_api_plain attack
90` is rc 139 without gdb; safe is rc 0. A plain real server with the
six-entity OPTIONS request and `MaxRequestsReallocateMem 0` returns 200
OK and exits 139 (`live/run.sh` only reports ASAN=NO, so the exit status
was captured directly). Raw outputs in `../evidence/w6-*.out`. This is a
negative rung-5 measurement: the second `free()` argument is glibc
free-list metadata, not wire-controlled; other allocators/builds are
UNKNOWN.
