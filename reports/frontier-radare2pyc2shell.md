# Frontier brief: radare2 PYC ASCII size-wrap heap WRITE — CVE-2026-81878 / GHSA-9phv-v2w8-56j3

Status: **STAGED 2026-11-26 W243**. Window 168 created and registered below;
operator admission owed; witness W243 replay ESTABLISHED AS LABELED, no
grade change, NO r5. Rung 3 pinned verbatim function and sink (GCC+Clang
ASan heap WRITE); rung 4 PARTIAL (a four-byte crafted marshal length field
selects the ~4GB write length; the plain lane logs sink arguments and writes
8 bounded bytes in a synthetic process — no written-byte readback, no
chosen fill byte). No
radare2/`rabin2` build, no crafted `.pyc` through the real binary-loader path,
no chosen-address pointer, no command and no rung 5.

## Claims

- CVE-2026-81878 / GHSA-9phv-v2w8-56j3, published 2026-08-11, Moderate 5.5,
  CWE-190 + CWE-787: radare2's CPython bytecode (`.pyc`) marshal parser accepts a
  32-bit attacker-controlled length in the `TYPE_ASCII` / `TYPE_ASCII_INTERNED`
  readers. `0xffffffff` makes the `size + 1` allocation wrap to zero; the byte
  reader then pads the unread portion with `0xff`, writing ~4GB past the
  undersized heap buffer. Advisory claims `<= 6.1.8` affected, `6.1.9` patched.
- Sources: `https://github.com/radareorg/radare2/security/advisories/GHSA-9phv-v2w8-56j3`,
  upstream issue `https://github.com/radareorg/radare2/issues/26222`
  (reporter's full chain and PoC recipe), fix
  `https://github.com/radareorg/radare2/commit/6727454b666b28c33837b219a5f91136461357c0`
  ("Fix heap write overflow in Python loader ##crash", 2026-07-06).
- Fix commit parent `838df53eaadc57b72a28bead5d8368f1ae37976d`. It changes only
  `libr/bin/format/pyc/marshal.c`: adds `if (size >= ST32_MAX) return NULL;` to
  `get_bytes()`, fixes two `get_long_object()` `hexstr[--j]` bounds, and adds
  `ST32_MAX` checks plus `(ut32)n + 1` casts in `get_complex_object()`.
- **Version discrepancy preserved:** no `6.1.9` tag exists in the public repo
  (tags jump `6.1.8` → `6.2.0`). Raw `marshal.c` at `6.2.0` contains the guard, so
  `6.2.0` is the first verified released fixed tag; the fix commit is the
  authoritative fixed source pin.

## Pins and source-bound mechanism

Byte-exact full files fetched by raw HTTP GET, hashes in
`lab/frontier/radare2pyc2shell/PROVENANCE.md`:

- `src/marshal-6.1.8.c` (affected release, byte-identical to fix parent),
  SHA-256 `41698e7886715b57427b166c90101aa132eadec821de66fccbf477a147cbb51c`.
- `src/marshal-fix-6727454.c`, SHA-256
  `3d8b2a625a96a750ad2135a32d975715f91a262d6bd71695b5ed9982bcf0c313`.
- `src/marshal-6.2.0.c` (first verified fixed release), SHA-256
  `0aedf7fb536fbfeb6c5cdb7804dce6a40e15807cfe107a0ac6c31c7115f4a45c`.
- `src/buf-6.1.8.c` (unchanged by the fix), SHA-256
  `538a6784eeb0e7f673625f73fce58e97c957f2b3dd41b90528d2f4b57493a52f`.
- Verbatim excerpts: `get_bytes()` vulnerable `marshal.c:78-85` (SHA-256
  `a3f2083495e1e6205fc77934167ae195a3968607bdc5b24f0aa653f6962c396f`) and fixed
  `78-89` (`8e41575a6e315364b95e125524db2fa9e28d8347b27dae8bf5c4004c95cff9ba`);
  ASCII readers `:615-644`, identical before and after the fix
  (`d19406980365f39859bcee067be6a940fcad812ddf23d0db48476484b16ed26e`);
  the sink statement `buf.c:496`
  (`4f3e1082ed37fd99f92d010c3b7037ef955583c9b795603d4c1de89892d5c9dd`).

Mechanism, verbatim: `get_ascii_object()` (`marshal.c:628-635`) reads a
`ut32 n` via `get_ut32()` and passes it to `get_ascii_object_generic()` →
`get_bytes(buffer, n)` with none of the `n > ST32_MAX` clamp its six sibling
string/collection readers apply. `get_bytes()` at `:79` computes
`R_NEWS0 (ut8, size + 1)` in 32-bit `ut32` arithmetic: `0xffffffff + 1` wraps to
`0`, so `calloc(0,1)` returns a minimal non-NULL chunk. `:80` then calls
`r_buf_read (buffer, ret, size)`. In `r_buf_read()` (`buf.c:491-497`) the actual
read returns `r` bytes present, then `memset (buf + r, b->Oxff_priv, len - r)`
runs **before** the caller's `< size` post-check; with `r = 0` and
`len = 0xffffffff` the length is `4294967295`. The fix's guard rejects the
length before the allocation and never reaches the sink.

## Local evidence

`bash lab/frontier/radare2pyc2shell/run-all.sh`: **31 PASS / 0 FAIL**, rc 0.
The harness compiles the pinned `get_bytes()` and ASCII readers verbatim under
`#line`, with stand-in `RBuffer`, `R_NEWS0`/`R_NEW0`, `get_ut32()` and
`buf_read()`; it does not build radare2. GCC and Clang `-O0` ASan report
`AddressSanitizer: heap-buffer-overflow`, `WRITE of size 4294967295`, at an
address `0 bytes after a 1-byte region` (the `calloc(0,1)` request wraps to
zero; ASan's usable chunk is one byte). ASan frame #0 is `memset` /
`__asan_memset`, frame #1 is `r_buf_read pins/buf-sink.inc:496`, frame #2
`get_bytes pins/get-bytes-vulnerable.inc:3`; allocation frame #0 is `calloc`,
frame #1 `get_bytes pins/get-bytes-vulnerable.inc:2` (the pinned `R_NEWS0`
call). Fixed
build on the same four-byte `ff ff ff ff` stream: `MODE=attack
LEN_FIELD=4294967295 RC=3 SINK=0`, ASan-clean. Safe 16-byte stream:
LEN_FIELD=16 RC=0 SINK=0` in both builds. Plain instrumented build logs
`SINK_BUF=<addr> SINK_R=0 SINK_LEN=4294967295 SINK_BYTE=ff` and performs an
8-byte `memset` through the sink stand-in, then returns `RC=3 SINK=1` —
direct evidence that the caller's post-check fires only after the sink has
written. It does not read the written bytes back; `SINK_BYTE=ff` is the
driver's fixed `b->Oxff_priv` (`harness/driver.c:136`), not a byte selected
by the crafted stream. Plain fixed build: `RC=3 SINK=0`. Exact commands,
hashes and logs: the lab `PROVENANCE.md`.

## Grade and tractability

- **Rung 3:** GCC and Clang ASan-confirmed heap OOB WRITE from verbatim pinned
  bytes, with fixed-commit, fixed-release and safe-input controls.
- **Rung 4 PARTIAL:** a four-byte attacker-selected marshal length field drives
  the sink length (`4294967295`); the plain lane logs the sink arguments and
  performs a bounded 8-byte fill past a zero-byte `calloc` request (ASan:
  a 1-byte region) in a synthetic process. No written-byte readback, no
  chosen fill byte, no real `.pyc`, no `rabin2`/`r2` build, no pointer
  control, no command.
- **Not rung 5:** no live loopback target and no benign command side effect.

W244 real-consumer outcome (2026-11-26): built radare2 6.1.8 with ASan and
drove `crafted-ascii.pyc` (magic `0x0a0d0d2c`, TYPE_ASCII length `0xffffffff`
at parse offset `0x22`) through `rabin2 -s` and `radare2 -q -c 'is'`. Probes
show `get_ascii_object n=4294967295`, `get_bytes alloc_arg=0 usable=1`, then
`r_buf_read len=4294967295 r=-1`: the IO-backed reader's `r_io_fd_read()`
takes `int len`, truncating the length to `-1`, so `buf.c:496`'s memset is
skipped. No ASan report on the unmodified build; no out-of-bounds write on
the real consumer. Grade unchanged: rung 3 pinned verbatim / rung 4 PARTIAL
synthetic, no real-consumer rung 4 and no r5. This negative is preserved in
`lab/frontier/radare2pyc2shell/PROVENANCE.md`; replay with `craft_pyc.py`,
`instrument_real.py` and a fresh 6.1.8 ASan build. The no-pointer/no-command
ceiling stands. Other RBuffer kinds (bytes/mmap/cache) were not driven by
these two CLI paths and remain UNKNOWN, not a pass.

## Duplicate check

`reports/frontier-*.md`, the frontier wall's do-not-duplicate list and
`lab/frontier/` were checked before provisioning. radare2 had no brief, lab or
window. No external system was probed; only advisory, issue, commit and public
raw-source fetches.
