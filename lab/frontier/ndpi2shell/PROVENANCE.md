# ndpi2shell — provenance, pins, negatives

W161, 2026-11-23. Everything here is provisioning + lab-local execution. No
external host was probed; advisories and source were fetched read-only.

## Claim

- GHSA-c8vx-3h2j-4f8m / CVE-2026-86098, GitHub Advisory Database, Unreviewed,
  High 7.4, CWE-787. Advisory summary: nDPI versions before 6.0 contain a heap
  buffer overflow in `ndpi_json_string_escape()` that writes beyond a
  caller-supplied buffer; crafted network packet data including TLS SNI, HTTP
  headers or DNS names can reach it. The advisory's numeric fixed version
  ("6.0") is a claim recorded from the advisory text; the fix itself is
  verified at the commit below.
- Upstream fix commit referenced by the advisory:
  `94e82c1de12323d992895830231865736a8abf2c` ("Fixes the following bug",
  Luca Deri, 2026-08-25). Its commit message is a reporter write-up naming
  `ndpi_serializer.c:90-163`, CWE-787, CVSS 7.4, affected "nDPI <= 5.0, HEAD
  commit ea3586e" and "Lab verified (ASan confirmed)". Treated as a claim,
  reproduced locally below.
- Advisory references: NVD CVE-2026-86098, the fix commit above,
  `https://github.com/ntop/nDPI/blob/5.0/src/lib/ndpi_serializer.c`, and a
  VulnCheck advisory page. Only GitHub advisory API + raw GitHub source were
  fetched; none of the linked third-party pages were used as evidence.

## Provisioning commands (verbatim shape)

```
curl -sS -H 'Accept: application/vnd.github+json' \
  https://api.github.com/advisories/GHSA-c8vx-3h2j-4f8m
curl -sSL https://github.com/ntop/nDPI/commit/94e82c1de12323d992895830231865736a8abf2c.patch
curl -sSL https://raw.githubusercontent.com/ntop/nDPI/94e82c1de12323d992895830231865736a8abf2c%5E/src/lib/ndpi_serializer.c \
  -o lab/frontier/ndpi2shell/src/ndpi_serializer.c.vuln
curl -sSL https://raw.githubusercontent.com/ntop/nDPI/94e82c1de12323d992895830231865736a8abf2c/src/lib/ndpi_serializer.c \
  -o lab/frontier/ndpi2shell/src/ndpi_serializer.c.fixed
```

## Pins

`PINS.sha256` records all four hashes: the two full raw files and the two
verbatim slices extracted by `harness/run.sh` (vulnerable lines 90-166, fixed
lines 90-226). `run.sh` calls `sha256sum -c` before generating drivers.
Rendered line numbers are claims; the raw bytes and `PINS.sha256` are
authoritative.

- Vulnerable function `ndpi_serializer.c.vuln:90-166`.
- Fixed function `ndpi_serializer.c.fixed:90-226`.

## Declared stubs and lab-only code

- `u_char` typedef (upstream typedef from a project header).
- Exact-size `malloc` for ASan builds; `malloc(dst_max_len+32)` with a `0xa5`
  canary for plain builds so bytes past the caller size are observable.
- Driver scenarios `baseline`, `escape`, `utf8`, `nul`; no ndpi library, no
  serializer struct, no packet capture, no socket, no wire, no consumer.
- Pinned slices are included under `#line 90 "ndpi_serializer.c.<variant>"`;
  all driver code is after `#line 1 "driver-tail.c"`.

## Mechanism read from pinned bytes

`:94` writes the opening quote without a bounds check. The loop guard at
`:96` is `j < dst_max_len`, tested once per source character, while a 2-byte
escape writes at `:106-107` and a 4-byte UTF-8 sequence writes at `:155-158`;
a check passing with `j == dst_max_len-1` therefore permits stores past the
caller size. After the loop, `:162` writes the closing quote and `:163` writes
the NUL at `dst[j+1]` rather than `dst[j]`, an unconditional off-by-one.

Fix `94e82c1` rejects `dst_max_len < 3`, sets `safe_max_len = dst_max_len - 2`,
adds a `j+N > safe_max_len` precheck to every escape branch, moves the
lookahead length checks ahead of the UTF-8 reads, writes NUL at `dst[j]`
(`:219`), and returns `-1` via an `overflow` label (`:222-225`).

## Observed evidence

- `harness/run.sh` builds 8 binaries (gcc/clang x vuln/fixed x plain/asan).
- `harness/check.sh`: 32 invocations + 2 gdb probes, `172 PASS / 0 FAIL` on
  three consecutive runs, trace
  `16060f55dfe944bf5e481a43e76034f6cd3d7acc159d561beaa067c8c97f7b5b`.
- gcc and clang ASan both report `heap-buffer-overflow`, `WRITE of size 1` at
  pinned `:107` (escape), `:158` (4-byte UTF-8) and `:163` (off-by-one NUL).
- Plain vulnerable tail bytes: escape `2f 22 a5 00`, utf8 `80 22 a5 00`,
  nul `a5 00 a5 a5` at offsets `dst_max_len..dst_max_len+3` (canary `a5`
  shows the skipped byte between closing quote and misplaced NUL).
- Fixed build returns `rc=-1` on all three attacks, leaves the canary intact,
  and triggers no ASan report. Baseline returns `rc=5` in all variants.
- gdb: at `:107`, `J=8 C=0x2f` — chosen `0x2f` is the byte stored at
  `dst[8]`, one past an 8-byte caller buffer. After return, `x/8xb dst+8`
  shows `0x2f 0x22 0xa5 0x00`, matching the plain tail.

## Preserved negatives / limits

- ASan aborts before stdout flush in vulnerable attack runs, so those outputs
  have no `scenario=`/`rc=` line; `check.sh` does not assert one there.
- The advisory's wire reachability (TLS SNI / HTTP / DNS) is a claim. The
  reporter's own patch text says internal callers are protected by a +24-byte
  over-allocation; this harness reproduces the external public-API condition
  (exact-size caller buffer), not an in-tree caller. No real nDPI build,
  packet, parser path, socket, pointer chain, command or witness replay.
- Fixed release "6.0" is advisory prose; only the fix commit bytes were
  fetched. Numeric fixed version is treated as UNKNOWN until a release tag is
  checked against the commit.
- Rung 5 UNKNOWN.

## W162 — real pinned nDPI build, caller analysis (2026-11-23)

Provisioning: `curl -sSL .../ntop/nDPI/tar.gz/94e82c1...%5E` (HTTP 200,
48 MB) extracted to `src/ndpi-full-vuln/`; its `src/lib/ndpi_serializer.c`
sha256 `4840fb417e420f3821746635f72ad2755d9f802a6ceb041450efb8efe9779ad5`
matches the pinned vulnerable file exactly. `./autogen.sh` then
`CC=clang CFLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O1'
LDFLAGS='-fsanitize=address' ../configure --disable-shared --enable-static
&& make -j4` in `build-asan/` produced `src/lib/libndpi.a` and
`example/ndpiReader`. Neither the upstream tree nor the build is committed.

Reproducer: `realbuild/run.sh` (fetch/build guarded), `realbuild/driver.c`
linked against the real `libndpi.a`. Three modes:

- `direct`: public `ndpi_json_string_escape` with an exact-size 8-byte malloc.
  ASan `WRITE of size 1` at `:107:18` in the real library, stack frame in
  `driver.c`, allocation from `driver.c:21`. `direct.out`.
- `real`: real JSON serializer, crafted VALUE strings (all `/`, repeated 4-byte
  UTF-8 `F0 90 80 80`, mixed escapes, strlen-based), init buffers 8/16/32/64/
  128, lengths 1..2000 — 145 cases, rc=0, **zero** ASan reports (`real.out`).
  Output contains `7b 22 6b 65 79 22 3a 22 5c 2f 22 7d` (`{"key":"\/"}`),
  proving the escape ran. Cause: the VALUE caller at `:1296-1310` pre-extends
  by `24 + slen*2`. This is a measured negative against the advisory's claim
  that SNI/HTTP/DNS-as-VALUE reaches an overflow in this build.
- `weakkey`: three real in-tree callers compute `needed = klen + 16` while the
  escape writes up to `2*klen+3`: `ndpi_serialize_start_of_block_binary`
  (`:2328,:2340`), `ndpi_serialize_start_of_list_binary` (`:2245,:2257`),
  `ndpi_serialize_binary_boolean` (`:2181,:2194`). With a key of 128 `/` bytes
  and the default 256-byte buffer, ASan reports `WRITE of size 1` at `:107:18`
  in `ndpi_json_string_escape`, called from
  `ndpi_serialize_start_of_block_binary:2340`, at address 0 bytes past the
  256-byte `calloc` from `ndpi_init_serializer_buffer:209` — the stored byte
  is the chosen key char `0x2f`. With klen=256 the first report is `:163:12`
  (off-by-one NUL), 1 byte past a 516-byte `realloc` from `:286`/`:2331`.
  Full enumeration in `realbuild/enumeration.txt`: klen 16/32/64 clean,
  128..2048 overflow for all three callers.

Grade: rung 3 ASan-confirmed and rung 4 chosen-byte-at-chosen-offset now come
from a REAL in-tree nDPI caller (not only the sliced stub). No packet, socket,
pointer control or witness verdict. The long key is supplied by the public
API probe; in-tree call sites pass constant field-name keys, except the
deserializer TLV-to-JSON conversion at `:3065,:3072` whose keys are described
as deserialized TLV keys. Whether network data can become such a key is
UNKNOWN, so the advisory's wire-reachability claim stays unproven; rung 5
UNKNOWN. Fixed-version "6.0" still UNKNOWN (no release tag checked).

## W162 — end-to-end reader negative (2026-11-23)

Ran the ASan-built `example/ndpiReader` on loopback-local pcap files only;
no network probe. Commands from `src/ndpi-full-vuln/`:

```
ASAN_OPTIONS=detect_leaks=0 ./build-asan/example/ndpiReader \
  -i tests/cfgs/dns_sub_enable/pcap/dns.pcap -k /tmp/ndpi-dns-out.json -K json
python3 /tmp/mk_http_pcap.py
ASAN_OPTIONS=detect_leaks=0 ./build-asan/example/ndpiReader \
  -i /tmp/ndpi-longhost.pcap -k /tmp/ndpi-http-out.json -K json
```

The second pcap is generated by the committed `realbuild/mk_longhost_pcap.py`:
one Ethernet/IPv4/TCP HTTP GET whose `Host:` header is 400 `/` bytes, the
maximum expansion input for the escape. Observed: both runs rc=0, zero
`ERROR: AddressSanitizer` lines, 6331-byte and 3305-byte JSON files. The HTTP
reader identified the flow and `reader-longhost.json` contains 560 `\/`
escapes including the untrusted Host value under `"http"`, proving the actual
packet-to-serializer-to-escape path ran without overflow. Outputs saved as
`realbuild/reader-{dns,longhost}.{out,json}`.

This is a real packet-path negative for SNI/HTTP/DNS-as-VALUE. It does not
reach the weak-key callers: their keys are constant field names in the reader
and dissectors. Wire reachability of the KEY overflow stays UNKNOWN.

## W162 — fixed-commit control (2026-11-23)

Fetched the fixed commit tree
`https://codeload.github.com/ntop/nDPI/tar.gz/94e82c1de12323d992895830231865736a8abf2c`
(HTTP 200); its `src/lib/ndpi_serializer.c` sha256
`0aa83a8317beb2f84a0d5c23016e9b4cfb5edb81f70c9aac3d1c13609aee92fd` matches
the pinned fixed file exactly. Built it with the same clang ASan flags in
`src/ndpi-full-fixed/build-asan/` and linked the same `driver.c` against its
`libndpi.a`. Modes `direct`, `real` and `weakkey` (all key lengths and all
three weak callers) returned rc=0 with **zero** `ERROR: AddressSanitizer`
lines (`realbuild/fixed-{direct,real,weakkey}.out`). The fix's
`j+N > safe_max_len` prechecks and NUL at `dst[j]` close the real-caller
overflow. Callers still ignore the `-1` return, so `size_used` can decrement;
that is a separate correctness issue, not memory corruption observed here.

## W162 — fixed release tag resolved (2026-11-23)

`git clone --bare --filter=blob:none --no-checkout https://github.com/ntop/nDPI.git`
into `/tmp/ndpi-refs` (provisioning only), then:

```
git tag --contains 94e82c1de12323d992895830231865736a8abf2c
  -> 6.0
     6.1-qubitowl
git describe --tags --contains 94e82c1... -> 6.0~14
git tag --list '5.*' -> 5.0
git log -1 --format='%H %cI %s' 6.0
  -> 1a5293396337f9a72dfee1fa070b2c4b0a0a3aaf 2026-08-28T11:57:03+02:00 Set new release version
```

The fix commit (2026-08-25) is an ancestor of tag `6.0`; only tags `6.0` and
`6.1-qubitowl` contain it, and the only 5.x tag `5.0` does not. The advisory's
numeric fixed release "6.0" is therefore confirmed by tag ancestry, replacing
the earlier UNKNOWN. This does not change the rung grade.

Key-reachability lane closed for this tree: grep for
`ndpi_deserialize_clone_all` / `ndpi_deserialize_clone_item` across the full
source tree finds only the declaration in `ndpi_api.h:1891-1892`, the
definitions in `ndpi_serializer.c:3000,3048`, `fuzz/fuzz_serialization.cpp:156,170`
and `tests/unit/unit.c:247`. No reader, dissector or daemon calls the TLV
clone. Every other key passed to the three weak callers is a literal field
name or a decimal number of at most 10 bytes (`ndpi_serializer.c:2374-2383`).
So no network path in this build can supply a >128-byte key to the overflow;
wire reachability of the KEY overflow is a negative for this tree, not merely
UNKNOWN. Rung 5 remains UNKNOWN and unreachable via this primitive.
