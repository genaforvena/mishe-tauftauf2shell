# Provenance — sofiasip2shell direct-call harness

## Pins (raw files fetched read-only from GitHub; no probing)

- Vulnerable tag `v1.13.17` = `6198851a610b7889c17e2d98fb84617bc1dd7aec`,
  `libsofia-sip-ua/tport/ws.c` saved as `../src/ws-1.13.17.c`, sha256
  `90ef747fef0221c038703bfa18b9ba1144761fc617047483631afb543194ff26`;
  `ws.h` saved as `../src/ws-1.13.17.h`, sha256
  `2ddb65497cac3e2c40729e7f34e2a959033c71356a4bdd50943f02bdd3e8b7b3`.
- Fixed tag `v1.13.18` = `ad36ac8f755308e8b87f98a505e83d4e408e5cc3`,
  `ws.c` saved as `../src/ws-1.13.18.c`, sha256
  `7c0b8b55cf4010e4dd3d4dd65dd91be06697e925026d8efc2d1a9425c7a946e7`;
  `ws.h` saved as `../src/ws-1.13.18.h`, sha256
  `34cf6c56abb87886bd909a2cb86f7b812d1f4613066cde490cf913cedfeefb12`.
- Fix diff `v1.13.17..v1.13.18` limited to `ws.c` and `ws.h` saved as
  `../src/fix-1.13.18.patch`, sha256
  `b3eefca29b3d14f9377a5359024225d26562f99b9556caed79edb968754f49f0`.
- Advisory: `GHSA-whfw-c3jj-99rp` / `CVE-2026-116791`, published 2026-10-28,
  affected `<= 1.13.17`, patched `>= 1.13.18`.
- All pin hashes are recorded again by each run in `evidence/pin-hashes.txt`.

## Extraction and instrumentation boundary

`gen_fn.py` locates the column-zero declaration of `ws_read_frame`, brace-matches
to its closing brace, and writes `fns-<pin>.inc`. `verify_verbatim.py` asserts
the slice is an exact substring of the pinned source. Both are checked on every
run before any compilation.

`harness.c` supplies only:

- the pinned `wsh_t` field layout and enums from `ws.h` (only `SSL`/`SSL_CTX`
  are forward-declared instead of included from OpenSSL headers);
- `ntoh64` copied from the pinned `ws.c`;
- deterministic stubs: `ws_raw_read` / `ws_raw_read_blocking` feed a scripted
  frame, `establish_logical_layer` returns 0 (plain socket), `ws_close` returns
  -1, `ws_write_frame` returns the byte count;
- the driver that allocates `buffer` and `bbuffer`, sets `handshake=1` and
  `payload_size_max = 4 MiB`, builds a masked BINARY frame with a 64-bit length
  field, and reads back the bytes past the conceptual `bbuffer` allocation.

No socket, TLS, Sofia SIP stack, FreeSWITCH build, or wire input is used. No
external system was contacted with a probe; the clone and advisory page were
read-only provisioning.

## Buffer sizing (pin-derived, not invented)

- Vulnerable pin `ws_init`: `wsh->bbuffer = malloc(wsh->bbuflen);`
- Fixed pin `ws_init`: `wsh->bbuffer = malloc(wsh->bbuflen + 1);` (NUL slot)

The ASan build uses exactly those sizes. The plain build places `bbuffer` at the
front of a 128-byte arena filled with `0xEE`, so a byte past the conceptual
64-byte allocation is observable without an ASan redzone (see the standing
negative about poisoned redzones).

## Cases

- `vuln`: 64-bit length + mask, 64-byte payload into a 64-byte `bbuffer`.
  `datalen = 14 + 64 = 78`, `rplen = 64`; the vulnerable unmask loop runs to
  `i = 77`, writing 14 bytes at offsets 64..77 and then a NUL at offset 64.
- `safe`: same frame with a 48-byte payload. `datalen = 62`, `rplen = 48`; the
  vulnerable loop still writes 14 bytes past the *payload* but stays inside the
  64-byte allocation, so ASan is clean. This is the negative control.

## Assertion set (128 per run)

Two rounds (`r1`, `r2`) x two compilers (`gcc`, `clang`) x two pins x four
cases (ASan vuln, ASan safe, plain vuln, plain safe). ASan vuln on the vulnerable
pin requires `heap-buffer-overflow`, `READ of size 1`, `0 bytes after 64-byte
region`, a `ws_read_frame` frame and the unbuffered `PRECALL` setup line; the
fixed pin and all safe cases require no ASan report. Plain vuln on the vulnerable
pin requires `CHOSEN_BAD=0` with `0xEE ^ mask[i%4]` at offsets 65..77, a NUL at
offset 64, and an unchanged `0xEE` at offset 78 (14-byte extent); the fixed pin
requires `CHOSEN_BAD=1` and untouched sentinel. Plain safe requires
`SAFE_BAD=0` on both pins.

Normalized evidence strips PIDs, addresses, paths and whitespace only.
