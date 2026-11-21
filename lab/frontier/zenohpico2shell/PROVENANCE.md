# Provenance — zenohpico2shell (CVE-2026-130603 / GHSA-fw6g-3fgh-f6m6)

All bytes below were fetched read-only from upstream on 2026-11-21. No probe
contacted any external system; fetching sources and advisories is provisioning.
`gen_driver.py` SHA-256 verifies **every one of the seven pins** on each run and
exits 3 with `PIN DRIFT` before rewriting either driver if any byte changes.

| Pin | Source URL | SHA-256 |
| --- | --- | --- |
| `src/message.v1.10.1.c` (affected) | `https://raw.githubusercontent.com/eclipse-zenoh/zenoh-pico/1.10.1/src/protocol/codec/message.c` | `38ce4cef3e0b0f3f189f0a7bc205683c82553462e36e9a799224160e9f416eb9` |
| `src/message.v1.10.2.c` (fixed) | `https://raw.githubusercontent.com/eclipse-zenoh/zenoh-pico/1.10.2/src/protocol/codec/message.c` | `ab9045e14694768c70a11805ae3edcc19a4060d07a716e1eaca99d25dd06ac01` |
| `src/core.v1.10.1.h` (ZID layout) | `https://raw.githubusercontent.com/eclipse-zenoh/zenoh-pico/1.10.1/include/zenoh-pico/protocol/core.h` | `519a1b63a31aa07f9887abc480df26a118c00893fac1c05c43733bdc68de0db0` |
| `src/iobuf.v1.10.1.h` (read helpers) | `https://raw.githubusercontent.com/eclipse-zenoh/zenoh-pico/1.10.1/include/zenoh-pico/protocol/iobuf.h` | `559398bc0bfb4dc03204ffac39071e83682b1e2e3114b0c1009f812420c4c8ee` |
| `src/iobuf.v1.10.1.c` (zbuf reader) | `https://raw.githubusercontent.com/eclipse-zenoh/zenoh-pico/1.10.1/src/protocol/iobuf.c` | `bff30fa6b1b8799450a8f23f680285de4717ea863cd17c91cc3be812b509dc00` |
| `src/fix130603.patch` | `https://github.com/eclipse-zenoh/zenoh-pico/commit/9198576fe69f6af66a2ab4f12f579f72208d7b28.patch` | `43f15d14967733876d7104b391cb2eb140e5e0d8cb47008febb033ac5337d21b` |
| `src/advisory130603.json` | `https://cveawg.mitre.org/api/cve/CVE-2026-130603` | `37929f8a7ba193e5f5f89eab6abcc0c13972e00fb947e6885bcc954770b88ac8` |

Cross-checks (read-only): OSV record `https://api.osv.dev/v1/vulns/CVE-2026-130603`
and GitHub advisory `https://github.com/advisories/GHSA-fw6g-3fgh-f6m6` (both
Critical 9.3). The fix commit's parent is
`a51e13e90ad68d0fa807ad8dfcd61044cbf926db`; the 1.10.1 tag source and the
pre-fix parent source carry the same vulnerable function. A 2023 commit
`f51284e46d6b09378fb6e5b37e07e2910683a40a` originally introduced the fixed
16-byte ZID decode; it is not the CVE fix. Upstream PR #1345 adds three
regression tests. A scout reader reported vulnerable statements at `:85-87`;
the verbatim raw file downloaded above puts them at `:79-81`. All line numbers
in this harness are from the raw pinned bytes, not from a rendered reader.

## Verbatim source statements copied by `gen_driver.py`

Every line under a `#line` marker is copied byte-for-byte from its pin at its
true line number. The generator asserts all pin hashes first; copied ranges:

- Vulnerable driver: `message.v1.10.1.c:77-83` (entire
  `_z_id_decode_as_slice`, including the unchecked `uint8_t len` read at `:79`,
  the unbounded `_z_zbuf_read_bytes` at `:80` and the wrapped-length
  `memset(id->id + len, 0, 16 - len)` at `:81`) and `:102-112`
  (`_z_timestamp_decode`, including the call at `:107`).
- Fixed driver: `message.v1.10.2.c:77-88` (checks `len > sizeof(id->id)` at
  `:81`, rejects at `:83`, uses `_z_zbuf_read_exact` at `:85`, memsets
  `sizeof(id->id) - len` at `:86`) and `:107-117` (`_z_timestamp_decode`,
  call at `:112`).

`gcc -O0 -g` attributes the ASan WRITE frame to
`_z_id_decode_as_slice` at `message_v1.10.1:80`, the exact pinned copy call.
`core.v1.10.1.h:59-62` bounds the destination at 16 bytes;
`iobuf.v1.10.1.h:76-79` and `:128`, together with `iobuf.v1.10.1.c:162-164`,
show that the upstream reader asserts only SOURCE readability before `memcpy`
— there is no destination bound. Those are source-bound only, not copied into
the driver.

## Harness stand-ins (not upstream code)

`_z_zbuf_t` is a local pointer/position/length stand-in; `_z_zbuf_read`,
`_z_uint8_decode`, `_z_zint64_decode` and `_z_zbuf_read_exact` are local
implementations of the pinned helper contracts; `_Z_RETURN_IF_ERR`,
`_Z_ERROR_LOG`, `_Z_RES_OK` and the error constant are local definitions.
Three layouts are used: `exact` (16-byte `malloc`, for ASan), `guard` (16-byte
region ending at a `PROT_NONE` page) and `collab` (zeroed 4096-byte arena whose
bytes +16/+32/+48 are read back after the copy). A `chain` mode exercises the
copied timestamp caller on a stack object for the fixed reject path.

The vulnerable `memset` limb is **not executed**: the stand-in read helper
takes a `longjmp` immediately after the verbatim copy, because `16 - len` is a
negative `int` converted to a huge `size_t` and an unbounded zero-fill would
destroy the harness process. Rung 2/4 readbacks are after the copy only. No
Zenoh transport, message framing, allocator neighbour, pointer value, control
flow diversion or execution was observed. The advisory's "potential remote
code execution" is a claim, not a result here.

## Independent replays

Frontier replay from a clean `git archive HEAD lab/frontier/zenohpico2shell`
extraction, with a separate output directory: 10 PASS / 0 FAIL, rc 0,
both five-run groups
`sha256=080794c304ffa34b467a189c505f02318af437ecc43c3a0658d985f0632b9b3b`.
All seven pins matched and copied lines were byte-exact. Witness replay
requested on the chat tape; author replay is not acceptance.
