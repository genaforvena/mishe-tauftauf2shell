# W237 — real libxml2 v2.15.3 consumer-boundary evidence (2026-11-26)

## Build

Provisioned from `https://gitlab.gnome.org/GNOME/libxml2/-/archive/v2.15.3/libxml2-v2.15.3.tar.gz`
into `src/libxml2-v2.15.3.tar.gz`, SHA-256
`0da50c1415f4ec0364569d2119b1436ba837b31df44af28569d234272c23cf1f`.
Configured and built without sanitizers:

    cmake -S libxml2-v2.15.3 -B build -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=OFF -DLIBXML2_WITH_TESTS=OFF \
      -DLIBXML2_WITH_PYTHON=OFF -DLIBXML2_WITH_ICONV=OFF \
      -DLIBXML2_WITH_LZMA=OFF -DLIBXML2_WITH_ZLIB=OFF
    cmake --build build -j4

`build/libxml2.a` produced (target LibXml2 86%, rc 0). `bash run-real.sh`
rehashes the tarball, rebuilds when needed, recompiles both probes and asserts
the four result lines below; it prints `REAL REPLAY PASS` (observed rc 0,
2026-11-26 14:3xZ).

## Source-bound observation

`dict.c` v2.15.3 has no `xmlDictAddQName`. Its only production caller of
`xmlDictAddQString()` is `xmlDictLookupInternal()` at line 762; lines 681-687
reject `len > INT_MAX/2` (0x3fffffff) and `plen >= INT_MAX/2 - len` before the
call. A wrap-to-zero name needs `namelen ~= 0xfffffff0`, which is far above the
gate. `xmlDictLookup`, `xmlDictLookupHashed` and `xmlDictQLookup` all go through
that gate, so the public dictionary API cannot supply the wrapping length.
Parser names are smaller still: `include/libxml/parserInternals.h` defines
`XML_MAX_NAME_LENGTH 50000` and `XML_MAX_TEXT_LENGTH 10000000`;
`xmlParseNameComplex` (parser.c:3090-3112), `xmlParseNCNameComplex`
(parser.c:3197-3226) and `xmlParseNCName` (parser.c:3250-3277) reject longer
names with `XML_ERR_NAME_TOO_LONG` before any dictionary call.

## Measured real-library results

`probe.c` calls the public `xmlDictQLookup()` with a 15-byte prefix and an
anonymous mapping filled with `a` so the strlen-style hash traverses the whole
name. Exact lines from `evidence/real-safe.log`, `evidence/real-over.log`:

    MODE=safe PREFIX_LEN=15 NAME_LEN=16 WRAP32=32 RET=non-NULL SECS=0.000 DICT_SIZE=1
    MODE=over PREFIX_LEN=15 NAME_LEN=1073741825 WRAP32=1073741841 RET=NULL SECS=0.885 DICT_SIZE=0

`over` is `INT_MAX/2+2`, already above the gate; the real library returned
NULL, allocated no dictionary entry and did not fault. No chosen-byte write
past a pool was observed in the real library.

`parser-probe.c` feeds element names just past both parser caps. Exact lines
from `evidence/real-parser.log`:

    PARSER_PROBE NAME_LEN=50001 HUGE=0 DOC=NULL ERRCODE=68 MSG=StartTag: invalid element name
    PARSER_PROBE NAME_LEN=10000001 HUGE=1 DOC=NULL ERRCODE=68 MSG=StartTag: invalid element name

Both parses fail with `Name too long: NCName` on stderr; the parser never
supplies a huge name to the dictionary.

## Incomplete observation, preserved

A full wrap-sized `probe wrap` run (`NAME_LEN=0xfffffff0`) under
`/usr/bin/time -v` did not finish within the 300 s command timeout on this
host; it produced no stdout before being killed and left no process or
elevated memory use. It is **UNKNOWN**, not a gate pass or a gate failure.
The `over` case and the source bound already establish the structural gate
without requiring a 4 GiB resident name buffer.
