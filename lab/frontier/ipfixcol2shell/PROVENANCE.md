# PROVENANCE — ipfixcol2shell harness

All upstream decoder logic is **verbatim pinned source**. Harness-owned code
is limited to the driver, wire-input generator and five replacement headers.
Loopback only in spirit: the driver feeds bytes through a local `pipe(2)`; it
never opens a socket and never contacts a network peer.

## Pins (fetched 2026-11-21, sha256 verified by `run.sh`)

| file | sha256 | source |
|---|---|---|
| `pins/Lz4Decoder.v2.7.1.cpp` | `3e618628ef0af35ad57f05afdb6a42cafe64403f846364d094f0381e7695fd10` | `raw.githubusercontent.com/CESNET/ipfixcol2/v2.7.1/src/plugins/input/tcp/src/Lz4Decoder.cpp` |
| `pins/Lz4Decoder.v2.8.0.cpp` | `3e618628ef0af35ad57f05afdb6a42cafe64403f846364d094f0381e7695fd10` | same path at tag `v2.8.0` |
| `pins/Lz4Decoder.v2.9.0.cpp` | `46a0fc8b98ed9a0b5b31567610211a771c22a241981d2dbbd4237fec0dfbcd14` | same path at tag `v2.9.0` |
| `pins/Lz4Decoder.hpp` | `926abbbfe33e91439f1d2c73afaeecad0d970e52bf854e97772ffe0b2b56f9fb` | v2.8.0 header |
| `pins/DecodeBuffer.hpp` | `de77de2accacbc665ca13ef0223b13c90cd2bc854dca9ca268b2341345878197` | v2.8.0 header (recorded, replaced by stub at build time) |
| `pins/read_until_n.hpp` | `274648538c050f75fd199514d7b05e07218703aedf63f483b2e42cf0fb26411d` | v2.8.0 header (recorded, replaced by stub at build time) |
| `pins/fd5cb168.patch` | `2be32ba279c3112a9ce8f59b8059145210ffdb04969722c50358b418c3bb4bb7` | `github.com/CESNET/ipfixcol2/commit/fd5cb168efb4b864d33f655174711b2779cef502.patch` |
| `pins/commit.json` | `6dcd1b0c1cf13599e7107adf3971d589901a725cc5f71e8ccea8cc3c131ecb19` | GitHub API commit record |
| `pins/tag-v2.8.0.json` | `244cf926badc553bab3542b07ca7d21c6c0d93f37070ec1fbe566f223a65c43a` | GitHub API git ref |
| `pins/tag-v2.9.0.json` | `010c47d8de7232de3924d76a6c92a93778bbc092e3e5c2d2fd74e7d576c2ad89` | GitHub API git ref |
| `pins/advisory.html` | `4152c637004093f9e15568509117ec7dde10c298f478524849a5fe48632928da` | `github.com/advisories/GHSA-4575-chq4-crfc` |

`gen_driver.py` copies the pinned `.cpp` and `.hpp` byte-for-byte, prefixing
only `#line 1 "<pinned name>"` so ASan frames show pinned filenames and lines.
`run.sh` re-checks that the staged bytes equal the pins after stripping that
one line (`pinned_sources_verbatim`).

## Harness-owned stubs (`stubs/`)

- `lz4.h` — ABI declarations only, because this host has `liblz4.so.1` but no
  `lz4-dev`; the real shared library is linked in every build.
- `Decoder.hpp`, `DecodeBuffer.hpp`, `read_until_n.hpp`, `ipfixcol2.h` —
  minimal stand-ins for the plugin's supporting API. `DecodeBuffer` records
  the bytes handed to it and stops the decode loop after any output;
  `read_until_n` reads from the pipe. Neither changes decoder logic.
- `driver.cpp` — feeds a wire file to the decoder and prints normalized facts.
- `gen_input.py` — builds the wire bytes: a start header with attacker-chosen
  ring size 24, then a per-message header with attacker-chosen
  `decompressed_size=65000` (and matching compressed size), then one
  all-literals LZ4 block whose literals are the chosen bytes. `declared=65000`
  is below the 65535 compressed-size field limit after LZ4 overhead; the
  advisory's "up to 65535" ceiling is not needed to demonstrate the bug.

## Repairs and negative results preserved

1. First compile used `-I pins -I stubs`; quoted includes inside `pins/` chose
   the real `DecodeBuffer.hpp`, which pulls in `ByteVector.hpp`. Fixed by
   staging the pinned `.cpp` into `out/` and generating the pinned header into
   `stubs/`, so only harness headers resolve.
2. Pinned `Lz4Decoder.cpp:180` calls `::read_until_n` (global namespace);
   the first stub declared it only in `tcp_in`, so compilation failed. Fixed
   by declaring the stub in the global namespace.
3. First wire attempt used `decompressed_size=65535`; with LZ4 literal-length
   overhead the compressed size exceeded the `uint16_t` header field and
   `struct.pack` rejected it. Reduced to 65000; the OOB remains ~65 kB past a
   24-byte allocation.
4. With default `-O1` inlining, the ASan allocation stack did not show
   `reset_stream` pinned `:184`. ASan builds now use `-O0 -fno-inline`, which
   reports allocation at `:184` via `read_start_header` `:131` and the
   overflowing call at `decompress` `:145`.
5. The chosen-byte build replaces global `operator new` with a 1 MiB mmap
   arena for exactly one 24-byte allocation (armed only around `decode()`).
   It is an **instrumented collaborator**, not a claim about stock allocator
   behavior: the stock/vulnerable ASan build faults before those bytes can be
   read back. The 0x41 differential and the benign all-zero control show the
   bytes are wire-controlled, not mmap residue. No pointer control, no return
   address, no marker execution.

## Rung evidence

- Rung 1: vulnerable build faults on the crafted wire input; fixed build throws
  `LZ4 Decoder: invalid decompressed size`; benign 8-byte input decodes clean.
- Rung 2: the decoder accepts 65000 as the destination capacity for a 24-byte
  ring (`out_bytes=65000`), and the fixed validation rejects it in a plain,
  non-ASan build.
- Rung 3: ASan `heap-buffer-overflow`, `WRITE of size 65000`, `0 bytes after
  24-byte region`, allocation pinned `Lz4Decoder.v2.8.0.cpp:184`, write call
  at `:145`.
- Rung 4 INSTRUMENTED: chosen `0x5a` at offsets 0/24/28/64999 past the ring,
  `0x00` at 65000/65001 (write stops at the declared length); `0x41`
  differential at the same offsets; benign input leaves them zero.
  No stock-build chosen-byte claim.

Final `./run.sh`: 13 PASS / 0 FAIL, trace
`sha256=e9c06f530d09912603ed379913699b2f1e63e08ab64b8cfcefdae0b47f3cd89f`.
Trace lines normalize away ASan addresses, PIDs and absolute paths so clean
archive replays are byte-identical.
