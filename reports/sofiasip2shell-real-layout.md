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

W2 refined the answer with two further **natural** glibc geometries (same
verbatim pinned function, real loopback wire, no custom allocator). With a
65527-byte bbuffer request and full payload, the 14-byte extent starts only
one byte before the next chunk's `size` field, so 5 XOR bytes land in the
neighbouring object's **user data**. With the default 65536-byte `ws_init`
bbuffer and a 65544-byte frame, the real `ws.c:1057` realloc fires, the buffer
stays in place, and 6 XOR bytes land in the neighbour's user data. The
1.13.18 control leaves that data untouched. The primitive is therefore not
confined to allocator metadata: it can write a chosen repeating-XOR delta
into a live neighbouring object's data at chosen offsets.

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
same `before ^ mask[i%4]` delta. On this glibc and *this request size* the
overrun is an allocator-metadata write, not an adjacent-object-data write;
the W2 geometries below change that.

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
| `plain-v17-geom` | v1.13.17, plain, 65527 bbuffer/payload | 0 | 5 XOR bytes in neighbour user data, 8 in its size field |
| `plain-v17-realloc` | v1.13.17, plain, 65544 frame on default bbuffer | 0 | real realloc, 6 XOR bytes in neighbour user data |
| `plain-f18-geom` | v1.13.18, plain, 65527 bbuffer/payload | 0 | neighbour data and size untouched |
| `plain-f18-realloc` | v1.13.18, plain, 65544 frame | 0 | realloc moves buffer (`SNAPSHOT_VALID=0`); live neighbour object untouched |

## W2: chosen XOR delta in a live neighbour's user data

`real_layout.c` accepts a `geom` mode with an optional bbuffer length and a
`realloc` mode; the pinned `.inc` files are unchanged and their hashes are
still asserted by `run.sh`. All byte readbacks are from
`lab/sofiasip2shell/layout/evidence/`. A clean `git archive HEAD` replay into
`/tmp` required regenerating the two gitignored `.inc` files from the tracked
pinned `ws-*.c` with `harness/gen_fn.py` (hashes `b96477e0` / `42dce55f`);
after that `run.sh` gave rc 0 with the 12 expected per-case rcs and all four
new `.err/.out/.rc` files byte-identical to the committed evidence.

### 65527-byte bbuffer (`plain-v17-geom`)

Request 65527 has `malloc_usable_size = 65528`, so glibc's usable slack is
one byte. The next chunk's `size` field begins at `bbuffer+65528`
(`META_OFF=+1`) and its user data at `bbuffer+65536`. With `rplen=65527` and
`datalen=65541`, the unmask loop writes `bbuffer[65527..65540]`:

```
PRECALL PIN=v1.13.17 MODE=geom PAYLOAD=65527 BBUFLEN=65527 USABLE=65528 MASK=415a4243
VICTIM_OFF=65536 VICTIM_SIZE_BEFORE=9100000000000000
VICTIM_DATA_BEFORE=c3c3c3c3c3c3c3c3 VICTIM_DATA_AFTER=8299818082c3c3c3
VICTIM_SIZE_AFTER=d05a4243415a4243
META_OFF=+1 NEXT_SIZE_BEFORE=9100000000000000 NEXT_SIZE_AFTER=d05a4243415a4243
GEOM_VOFF=65536 GEOM_FIRST=9 GEOM_NBYTES=5 GEOM_VICTIM_DELTA_BAD=0
```

The first 5 victim bytes equal `0xC3 ^ mask[(65527+9+k)%4]` for k=0..4:
`82 99 81 80 82`. The next 8 bytes corrupt the whole victim chunk `size`;
the trailing NUL lands inside the bbuffer's usable slack. All 8 bytes of the
victim's `size` field change because the metadata boundary moved relative to
the requested length.

### Default bbuffer, real realloc (`plain-v17-realloc`)

A masked BINARY frame with a 65544-byte payload on the default 65536-byte
`ws_init` bbuffer satisfies `need + blen > bbuflen` at
`fns-1.13.17.inc:141`, so the pinned code takes the real realloc branch
(`ws.c:1057`) and grows `bbuflen` to 65544. glibc keeps the same chunk
(`USABLE=65544` before and after), so the neighbouring object stays at
`bbuffer+65552`. The unmask loop now runs to `bbuffer+65557`, i.e. 14 bytes
past the grown `rplen`:

```
PRECALL PIN=v1.13.17 MODE=realloc PAYLOAD=65544 BBUFLEN=65536 USABLE=65544 MASK=415a4243
PIN=v1.13.17 MODE=realloc RV=65544 DATALEN=65558 RPLEN=65544 BBLEN=65544 USABLE=65544 OC=2
VICTIM_OFF=65552 VICTIM_SIZE_BEFORE=9100000000000000
VICTIM_DATA_BEFORE=c3c3c3c3c3c3c3c3 VICTIM_DATA_AFTER=829981808299c3c3
VICTIM_SIZE_AFTER=005a4243415a4243
META_OFF=+8 NEXT_SIZE_BEFORE=9100000000000000 NEXT_SIZE_AFTER=005a4243415a4243
GEOM_VOFF=65552 GEOM_FIRST=8 GEOM_NBYTES=6 GEOM_VICTIM_DELTA_BAD=0
```

The first 6 victim bytes equal `0xC3 ^ mask[(65544+8+k)%4]` =
`82 99 81 80 82 99`. The 8 bytes of the neighbour's `size` field are also
changed, with the low byte zeroed by the trailing NUL at `p+65544`. This is
the default library buffer size and the library's own realloc path; no
non-default allocator or synthetic arena is involved.

### Controls

`plain-f18-geom`: `VICTIM_DATA_BEFORE == VICTIM_DATA_AFTER` (`c3` × 8), size
field unchanged, `GEOM_VICTIM_UNTOUCHED=1`. `plain-f18-realloc`: the fixed
pin's `+1` slot makes the 65545-byte realloc cross a chunk boundary and move
the bbuffer, so the pre-call byte snapshot is invalid
(`CONTROL=FIXED_PIN_REALLOC_MOVED SNAPSHOT_VALID=0`); the independently
allocated live 128-byte neighbour object is unchanged
(`GEOM_VICTIM_UNTOUCHED=1`). These are honest controls for object-data
corruption, not for a same-address byte-for-byte comparison in the realloc
case.

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

## Independent witness replay (2026-11-22)

Witness replay of the layout claim is **ESTABLISHED at the labeled scope**.
From a clean `git archive HEAD` of `lab/sofiasip2shell` and
`lab/frontier/sofiasip2shell` in `/tmp`, the witness regenerated both pinned
`fns-*.inc` from the tracked `ws-*.c` and confirmed the required hashes
`b96477e0` / `42dce55f`, then ran `layout/run.sh` twice: rc 0 both rounds,
identical per-case rc set (`asan-v17-vuln`=1, all other ASan/plain cases 0,
`plain-v17-abort`=134). 23 of 24 evidence files were byte-identical to the
canonical files; the only difference was the ASan log's PID/addresses/build
paths, which masked to identity. The specific requested checks all passed on
the witness run: `NEXT_SIZE_BEFORE=710c020000000000` →
`NEXT_SIZE_AFTER=30564043415a0000` with `XOR_DELTA_BAD=0` and `NUL=00` at
offset 0, `malloc(): corrupted top size` rc 134, victim `0xC3` data unchanged
with chunk size `d05a4243415a0000`, 65520-byte short frame untouched, fixed
pin clean, ASan `READ of size 1` at 0 bytes after the 65536 region in
`ws_read_frame` at `fns-1.13.17.inc:185`. The witness did **not** independently
rebuild the full autogen/configure/make library lane (its pin trees are
gitignored local artifacts); that lane remains author-observed from the
committed logs, not an independent rebuild. Grade unchanged.

## Honest grade

- **Rung 1/2**: deterministic real-frame trigger; `datalen=65550` vs
  `rplen=65536` state mismatch observed.
- **Rung 3**: ASan-confirmed out-of-bounds read/write at the real 64 KiB
  region in a full pinned-library build, plus a byte-level readback of changed
  allocator metadata.
- **Rung 4 (upgraded twice)**: an attacker-chosen repeating-XOR delta is
  written to 6 bytes of the next chunk's size field at the default geometry
  and the next allocation aborts. At two other natural layouts the same
  delta reaches a live neighbouring object's **user data** — 5 bytes with a
  65527-byte bbuffer, 6 bytes with a 65544-byte frame on the default bbuffer
  through the library's real realloc path. The chosen *delta* depends on the
  bytes already present; the attacker controls a 4-byte repeating mask, not
  arbitrary bytes. No pointer, length or control-flow value was targeted.
  Consequence demonstrated: heap-metadata corruption, deterministic process
  abort and chosen-delta corruption of adjacent object data; not a controlled
  pointer, marker or command.
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
- At the default 65536 request the natural next chunk is the top chunk;
  `plain-v17-victim` confirms the data gap there. W2's 65527 and 65544
  geometries close that gap with real glibc allocations, but both still write
  only a 4-byte repeating XOR delta at fixed offsets, not attacker-chosen
  absolute values. Four payload/length configurations (65520, 65527, 65536,
  65544) and one neighbour object type (128-byte chunk) were measured.
- W3 varied the 4-byte mask (`00000000`, `00000100`, `405a4243`, `415a4243`)
  and the bbuffer request size (65528–65536). Converting the delta into a
  *useful* heap state (overlapping chunks, pointer control) was not achieved;
  see the W3 section below.
- The fixed pin's 65544-byte realloc moves the buffer, so that control is a
  live-object check rather than a same-address byte comparison.
- Independent replay covers the layout harness only, not the full pinned
  library build; witness verdict ESTABLISHED is scope-labeled accordingly.
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

## W3: PREV_INUSE survival is mask-dependent but buys no usable heap state

W2's "the first corrupted byte clears PREV_INUSE" is true for the tested mask
`415a4243` and for the realloc geometry, but it is **not structural**. The
verbatim pinned loop writes 14 bytes as `old ^ mask[(rplen+k)%4]` for k=0..13
and then rewrites byte k=0 with a fixed NUL. Whether the next chunk's `size`
low byte is hit by the XOR or by the NUL, and whether it survives, depends on
glibc's usable slack (`malloc_usable_size - request`) and on the mask.

W3 added a `SIA_MASK=hex8` override to `real_layout.c` (frame bytes and the
readback check both use it; the pinned `.inc` files and `run.sh` hashes are
untouched) and an explicit `PREV_INUSE_BEFORE/AFTER` print. Raw cases are in
`lab/sofiasip2shell/layout/evidence/w3/`; the mask-capable binary is
`plain-mask`. Every delta check still passes (`XOR_DELTA_BAD=0`).

| Case | mask | `NEXT_SIZE_BEFORE` -> `AFTER` | PREV_INUSE | rc |
|---|---|---|---|---|
| default 65536, +malloc | `415a4243` | `710c020000000000` -> `30564043415a0000` | 1 -> 0 | 134 |
| default 65536, +malloc | `405a4243` | `710c020000000000` -> `31564043405a0000` | **1 -> 1** | **134** |
| geom 65527 | `415a4243` | `9100000000000000` -> `d05a4243415a4243` | 1 -> 0 | 0 |
| geom 65527 | `405a4243` | `9100000000000000` -> `d15a4243405a4243` | **1 -> 1** | 0 |
| realloc 65544 | either | `9100000000000000` -> `005a4243415a4243` | 1 -> 0 | 0 |

An even `mask[0]` does preserve PREV_INUSE at the default and 65527
geometries (the XOR, not the NUL, writes that byte there). It **does not buy
survival**: the same run still aborts with `malloc(): corrupted top size`
(rc 134). Reason, visible in the bytes above: the 14-byte extent covers six
low bytes of the size field, and original size bytes 3, 4 and 5 are zero; a
nonzero `mask[3]`, `mask[0]` or `mask[1]` turns them into `43 41 5a`, making
the top size `0x5a4043405631` — an implausible value that glibc rejects on the
next allocation irrespective of PREV_INUSE. In the realloc geometry the fixed
NUL lands on the size low byte itself, so PREV_INUSE is cleared for every mask.

Masks that leave those high bytes zero behave as expected:
`00000000` leaves the size unchanged; `00000100` changes only one plausible
size byte (`710c020000000000` -> `710c030000000000`); both survive the
post-frame `malloc(64)` (rc 0) with PREV_INUSE intact. The surviving masks are
exactly those that collapse the corruption to usable padding plus at most one
low size byte — no fake chunk, overlap or pointer.

A request-size slack sweep closes the other branch. With a 65529- or
65530-byte bbuffer request (`malloc_usable_size = 65544`, slack 15/14) the
whole 14-byte extent stays inside usable padding: `NEXT_SIZE_BEFORE ==
NEXT_SIZE_AFTER`, PREV_INUSE 1 -> 1, no corruption at all. Slack 0 (65528) is
the NUL-on-size-low-byte case (1 -> 0); slack 13 (65531) lets only the last
XOR byte touch size byte 0 (`91` -> `d0`, 1 -> 0). These configurations
either erase the primitive or keep it caught — none yields a controllable
fake chunk.

**Decision**: no tested mask/geometry combination turns PREV_INUSE survival
into a usable allocator state. Preserving the bit removes one abort message
but leaves an implausible size; restoring a plausible size removes the useful
corruption. Rung 5 on this primitive needs a different write mechanism, not
more grooming of this one. No pointer, marker, command or side effect was
measured; grade unchanged. W3 is author-observed and awaits witness replay.

Reproduce the W3 cases with
`bash lab/sofiasip2shell/layout/run_w3.sh` (rebuilds the plain harness,
re-asserts the pinned SHA-256, and writes `.out/.err/.rc` for all 15 cases to
`lab/sofiasip2shell/layout/evidence/w3/`). The canonical `run.sh` evidence is
unchanged: its only rerun diff is volatile ASan PID/addresses/build paths.
