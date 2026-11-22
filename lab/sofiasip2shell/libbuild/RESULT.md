# Real-library ASan drive: CVE-2026-116791 / GHSA-whfw-c3jj-99rp

## Outcome

**Confirmed at a full autogen/configure/make ASan build of pinned `libsofia-sip-ua`.**
With v1.13.17 (`6198851a`) and a real masked BINARY frame declaring/carrying
65536 bytes, ASan reports `heap-buffer-overflow` in the `ws_read_frame` call
path (first write: `ws_raw_read` called from `ws_read_frame`; in a recover-mode
build, also directly in `ws_read_frame`'s unmask loop). The 65520-byte
short-frame control and the fixed-pin v1.13.18 (`ad36ac8f`) control are clean.

## What was built (exact commands; logs in `evidence/`)

Pinned trees were exported with `git archive <tag> | tar -x` from the read-only
source at `lab/frontier/sofiasip2shell/src/sofia-sip` into `pins/v17`,
`pins/v18`, `pins/v17recover`. No tag was checked out in the shared tree; no
tracked file or other lab path was edited.

```
# pins/v17 (vulnerable) — evidence/v17-autogen.log, v17-configure.log, v17-make.log
$ ./autogen.sh
$ env CC=clang CFLAGS='-O0 -g -fno-omit-frame-pointer -fsanitize=address' \
    LDFLAGS='-fsanitize=address' ./configure --disable-shared --enable-static \
    --disable-stun --prefix=/tmp/sofia-libbuild-v17
$ make -C libsofia-sip-ua -j4 V=1          # -> libsofia-sip-ua/.libs/libsofia-sip-ua.a

# pins/v18 (fixed) — evidence/v18-build.log (all three commands in one log)
$ ./autogen.sh
$ env CC=clang CFLAGS='-O0 -g -fno-omit-frame-pointer -fsanitize=address' \
    LDFLAGS='-fsanitize=address' ./configure --disable-shared --enable-static \
    --disable-stun --prefix=/tmp/sofia-libbuild-v18
$ make -C libsofia-sip-ua -j4 V=1

# pins/v17recover (same vulnerable pin, ASan recover mode) — evidence/v17recover-build.log
$ ./autogen.sh
$ env CC=clang CFLAGS='-O0 -g -fno-omit-frame-pointer -fsanitize=address -fsanitize-recover=address' \
    LDFLAGS='-fsanitize=address' ./configure --disable-shared --enable-static \
    --disable-stun --prefix=/tmp/sofia-libbuild-v17recover
$ make -C libsofia-sip-ua -j4 V=1
```

All three builds succeeded; no fallback compile of a bare `ws.c` was needed.
`ws.c` SHA-256 matches `git show <tag>:libsofia-sip-ua/tport/ws.c` for every pin:

```
v17 / v17recover  90ef747fef0221c038703bfa18b9ba1144761fc617047483631afb543194ff26
v18               7c0b8b55cf4010e4dd3d4dd65dd91be06697e925026d8efc2d1a9425c7a946e7
```

## Driver and runs

`driver/real_ws_driver.c` includes the library's own `ws.h`, calls
`ws_set_global_payload_size_max(4 MiB)`, `ws_init(wsh, srv, NULL, 0, 10000, 1)`
on an accepted 127.0.0.1:0 socket after a real HTTP 101 upgrade, sets
`wsh->handshake = 1`, writes a masked 64-bit-length BINARY frame, then calls
`ws_read_frame(wsh, &oc, &data)`. `driver/build_and_run.sh <pin> <label> <mode...>`
compiles against the built static `.a` and records `$ ...` commands plus
per-case `.out`, `.err`, `.rc` in `evidence/`.

```
$ bash driver/build_and_run.sh v17 "v1.13.17" full short
$ bash driver/build_and_run.sh v18 "v1.13.18" full short
$ ASAN_OPTIONS_OVERRIDE='detect_leaks=0:abort_on_error=0:halt_on_error=0' \
    bash driver/build_and_run.sh v17recover "v1.13.17-recover" full short
```

| case (`evidence/<tag>.*`) | rc | ASan heap-buffer-overflows |
| --- | --- | --- |
| `v17-full` | 1 | 1 (first error, aborts) |
| `v17-short` | 0 | 0 |
| `v18-full` | 0 | 0 |
| `v18-short` | 0 | 0 |
| `v17recover-full` | 0 (recover mode) | 3 (reported, execution continues) |
| `v17recover-short` | 0 | 0 |

All driver diagnostics are on stderr; the `.out` files are empty by design.
Leak detection was disabled (`detect_leaks=0`) to keep reports focused on the
frame buffer.

## Key observed lines (absolute paths shortened to `...`; raw files in evidence/)

`evidence/v17-full.err` (default halt-on-error ASan build):

```
PRECALL PIN=v1.13.17 MODE=full PAYLOAD=65536 CAP=4194304 INIT_RC=0 HANDSHAKE=1 DATALEN=151 BUFFER=0x531000014800 BBUFFER=0x531000028800 BBUFLEN=65536
==4068635==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x531000038800 at pc 0x57453f313123 bp 0x7ffc3508d2f0 sp 0x7ffc3508d2e8
WRITE of size 1 at 0x531000038800 thread T0
    #0 0x57453f313122 in ws_raw_read .../pins/v17/libsofia-sip-ua/tport/ws.c:427:23
    #1 0x57453f317f1a in ws_read_frame .../pins/v17/libsofia-sip-ua/tport/ws.c:1073:17
...
0x531000038800 is located 0 bytes after 65536-byte region [0x531000028800,0x531000038800)
allocated by thread T0 here:
    #0 ... in malloc ...
    #1 0x57453f315c80 in ws_init .../pins/v17/libsofia-sip-ua/tport/ws.c:744:17
...
SUMMARY: AddressSanitizer: heap-buffer-overflow .../pins/v17/libsofia-sip-ua/tport/ws.c:427:23 in ws_raw_read
```

`evidence/v17recover-full.err` (same pinned source, `-fsanitize-recover=address`,
`halt_on_error=0`) — surfaces the direct `ws_read_frame` hits:

```
PRECALL PIN=v1.13.17-recover MODE=full PAYLOAD=65536 CAP=4194304 INIT_RC=0 HANDSHAKE=1 DATALEN=151 BUFFER=0x531000014800 BBUFFER=0x531000028800 BBUFLEN=65536
==4130836==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x531000038800 ...
READ of size 1 at 0x531000038800 thread T0
    #0 0x62ff1c5ce3ad in ws_read_frame .../pins/v17recover/libsofia-sip-ua/tport/ws.c:1090:19
SUMMARY: AddressSanitizer: heap-buffer-overflow .../pins/v17recover/libsofia-sip-ua/tport/ws.c:1090:19 in ws_read_frame
==4130836==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x531000038800 ...
WRITE of size 1 at 0x531000038800 thread T0
    #0 0x62ff1c5ce59e in ws_read_frame .../pins/v17recover/libsofia-sip-ua/tport/ws.c:1100:28
SUMMARY: AddressSanitizer: heap-buffer-overflow .../pins/v17recover/libsofia-sip-ua/tport/ws.c:1100:28 in ws_read_frame
POSTCALL PIN=v1.13.17-recover MODE=full RV=65536 DATALEN=65550 RPLEN=65536 BBLEN=65536 OC=2 DATA=0x531000028800
```

Clean controls (abridged; full lines are in the evidence files):

```
evidence/v17-short.err:   PRECALL PIN=v1.13.17 MODE=short PAYLOAD=65520 ... BBUFLEN=65536
                          POSTCALL PIN=v1.13.17 MODE=short RV=65520 DATALEN=65534 RPLEN=65520 BBLEN=65536 OC=2 DATA=0x531000028800
evidence/v18-full.err:    PRECALL PIN=v1.13.18 MODE=full PAYLOAD=65536 ... BBUFLEN=65536
                          POSTCALL PIN=v1.13.18 MODE=full RV=65536 DATALEN=65550 RPLEN=65536 BBLEN=65536 OC=2 DATA=0x531000028800
evidence/v18-short.err:   PRECALL PIN=v1.13.18 MODE=short PAYLOAD=65520 ... BBUFLEN=65536
                          POSTCALL PIN=v1.13.18 MODE=short RV=65520 DATALEN=65534 RPLEN=65520 BBLEN=65536 OC=2 DATA=0x531000028800
```

None of the four clean `.err` files contain `ERROR: AddressSanitizer`.

## Why the fix holds

In v1.13.17 `ws_init` allocates `bbuffer` with exactly `bbuflen = 65536`
(`ws.c:744`), the full frame needs no realloc, and `ws_read_frame` fills the
body up to `bbuffer+65536`; `ws_raw_read`'s terminating NUL write lands one byte
past the allocation. The unmask loop is bounded by `wsh->datalen` (65550: 14
header bytes plus 65536 payload) instead of the 65536 payload bytes, so it also
touches `body[65536..65549]`, and the final `*(body+rplen)='\0'` writes the same
byte again. v1.13.18 allocates one extra NUL slot and bounds the unmask loop by
`wsh->rplen`, so the same frame stays in bounds. The 65520-byte control fits in
the 65536-byte v1.13.17 allocation and never reaches the redzone.

## Honest limits

- The driver drives the real library API and real loopback TCP I/O, but stops at
  `ws_read_frame`; it does not exercise FreeSWITCH's SIP/tport binding, SDP,
  or a full call setup. No FreeSWITCH upgrade or rung 5 was attempted.
- The HTTP upgrade is real (`ws_init` performs `ws_handshake`, INIT_RC=0,
  HANDSHAKE=1), but the driver also explicitly sets `wsh->handshake = 1` as
  specified, immediately before feeding the frame.
- In the default ASan build, the first report's top frame is `ws_raw_read`
  (the NUL write at `ws.c:427`) with `ws_read_frame` as caller at `ws.c:1073`;
  the halt-on-error default prevents reaching the unmask loop. The separate
  recover-mode build of the *same pinned source* reports the direct
  `ws_read_frame` overflows at `ws.c:1090` and `ws.c:1100`. Its rc=0 is an
  artifact of `halt_on_error=0`, not a clean run.
- Only loopback sockets were used; no external probing. The pinned source tree
  was read-only, and nothing was committed.
