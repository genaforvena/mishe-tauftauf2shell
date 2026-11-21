# Real-build consumer-reality check — CVE-2026-19773

Loopback-only check of whether the pinned HPACK `:path` chosen-byte OOB is
reachable in a real libwebsockets server. Result: **negative for the naive
long-`:path` route**; the harness's rung-4 INSTRUMENTED grade is unchanged,
but the URI-delimiter route (W2, below) gives a real-build chosen-byte OOB.

## Provisioning (fetch only, no probe)

```
mkdir -p lab/libwebsockets2shell-src && cd lab/libwebsockets2shell-src
for tag in v4.3.10 v5.0.0; do
  curl -fsSL "https://codeload.github.com/warmcat/libwebsockets/tar.gz/refs/tags/$tag" -o "$tag.tgz"
  tar xzf "$tag.tgz"; mv "libwebsockets-${tag#v}" "$tag"
done
```

Both extracted `lib/roles/h2/hpack.c` files hash to the pins in
`lab/frontier/libwebsockets2shell/PROVENANCE.md`:
`5ce2d424…de5439` (v4.3.10) and `9232db68…8ea584` (v5.0.0).

## Build

```
cd lab/libwebsockets2shell-src/v4.3.10
cmake -S . -B build-asan -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DLWS_WITH_ASAN=ON -DLWS_WITHOUT_TESTAPPS=ON -DLWS_ROLE_WS=OFF \
  -DLWS_WITH_HUBBUB=OFF -DLWS_WITH_MINIZ=OFF -DLWS_WITH_ZLIB=OFF \
  -DLWS_WITH_LIBUV=OFF -DLWS_WITH_LIBEVENT=OFF -DLWS_WITH_LIBEV=OFF
cmake --build build-asan -j2
gcc -fsanitize=address -fsanitize=undefined -g -O0 -I include \
  -I build-asan/include -I lib -o ../h2server2 ../h2server.c \
  build-asan/lib/libwebsockets.a -lssl -lcrypto -lpthread -ldl -lm -lrt
```

TLS must be compiled in: `LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE` switches to
the H2 role via `lws_role_call_alpn_negotiated`, which is inside
`#if defined(LWS_WITH_TLS)`. The connection itself stays cleartext on
127.0.0.1.

For v5.0.0 add `-DLWS_WITH_GNUTLS=OFF -DLWS_WITH_HTTP3=OFF
-DLWS_ROLE_QUIC=OFF`, and `-DCMAKE_C_FLAGS=-fsanitize-recover=address` plus
`-fsanitize-recover=address` and `ASAN_OPTIONS=halt_on_error=0`: v5.0.0 has
an unrelated startup `stack-buffer-overflow` in
`lws_sa46_parse_numeric_address` (`network.c:947`) that fires during bind,
before any connection.

## Run (one probe)

```
ASAN_OPTIONS=detect_leaks=0 ./h2server2 18780 31 > server.log 2>&1 &
python3 h2client.py 18780 65        # or 200 / 201
```

`h2server.c` binds only 127.0.0.1 and sets `max_http_header_data = 32`.
`h2client.py` sends the HTTP/2 preface, empty SETTINGS and one HEADERS frame
whose HPACK literal `:path` (static index 5) decodes to N+1 bytes (leading `/`
from the client plus N filler bytes).

`trace.gdb` logs every store at raw `hpack.c:277`:

```
ASAN_OPTIONS=detect_leaks=0 gdb -q -batch -x trace.gdb --args ./h2server2 18783 1
# from another shell, while gdb runs:
python3 h2client.py 18783 65
```

## Observations (2026-11-21 W1)

- v4.3.10, preserved raw logs for client args 65 and 201 (decoded 66 and
  202): `http/2 prior knowledge`, `http2: ... established`, then
  `lws_hpack_interpret: frag app fail` and `lws_h2_parser: hpack failed`;
  no hpack ASan report. W70's independent replay saw neither fail at arg 8
  and only `hpack failed` at arg 30; the bottom line is unchanged. The gdb
  trace additionally covered args 8/16/30/31/32/33/64/100/200.
- gdb: 253 real stores across nine lengths, every one with `max=32` and
  `pos` in `0..31`, including NUL stores at `pos=9,13,18,28,31,...`.
  No store ever entered at `pos >= 32`.
- Source audit (W1): `:277` is the only direct `ah->pos` mutation in
  `hpack.c`; callers `:286`, `:744`, `:1168` all check the post-write return;
  `ah->data` is a separate `lws_malloc(data_size)` (`parsers.c:50`). W2 found
  that `lws_parse_urldecode` also mutates `ah->pos` (section below).
- v5.0.0 control: same `frag app fail` / `hpack failed`, no hpack ASan.

Raw logs are in `evidence/`. `gdb-boundaries.log` and `gdb-path65.log` are
complete gdb traces; the server logs include routine lws diagnostics.

## Confirmed URI-delimiter route (W2, 2026-11-21)

The W1 negative is specific to a plain long `:path`. `lws_parse_urldecode`
also mutates `ah->pos`: a literal `&`, `;` or `?` in `:path` takes the
delimiter branch (`&`/`;` at `parsers.c:862-877`, `?` at `:962-985`), where
`issue_char` writes a NUL (`:863`/`:968`) and `++ah->pos` (`:874`/`:978`)
advances again with no bounds check. The next literal path byte reaches
`hpack.c:1168` with `pos >= limit`, so the pinned `:277` store lands past
the arena.

Reproduce against the same ASan server (loopback only):

```
ASAN_OPTIONS=detect_leaks=0 ./h2server2 18781 7 > delim.log 2>&1 &
python3 h2client-delim.py 18781 30 '&' 5a
```

`h2client-delim.py PORT PREFIX DELIM MARKER [TAIL]` sends `/` + `A`*(PREFIX-1)
+ DELIM + MARKER*TAIL; MARKER may be a two-digit hex byte. PREFIX 30 enters
the delimiter at `pos=30` and stores the marker at `data[32]`; PREFIX 31
stores at `data[33]`.

Observed: ASan `WRITE of size 1` at raw `hpack.c:277` from `hpack.c:1168`,
0 or 1 bytes after the 32-byte arena; markers `5a`/`a5`/`37` and delimiters
`&`/`;`/`?` all fault. gdb on a non-ASan Debug build of the same pinned tree:
`OOB-ENTRY pos=32 c=0x37` then `READBACK data[32]=0x37` (also `0x5a`). v5.0.0
with the same frame gives `frag app fail` and no hpack ASan. Raw logs in
`evidence/`. No pointer or execution claim. Witness W72 independently
replayed this route on fresh builds and reported ESTABLISHED AS CLAIMED.

