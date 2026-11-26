# PROVENANCE — sngrepsip2shell (W298, 2026-11-26)

## Provisioning (read-only public sources, no probing)

All source fetches used `curl -fsSL` against raw.githubusercontent.com on
2026-11-26 (23:14Z), no source was modified after fetch. No external target
was contacted except these public source/advisory hosts.

| pin | source URL | SHA-256 |
|---|---|---|
| `pins/sip.c.vuln` | `https://raw.githubusercontent.com/irontec/sngrep/v1.9.0/src/sip.c` | `c195674a72b0223b669e8ef9b2fce0a01d6c4224dd6ea217acfb5cc757462b30` |
| `pins/sip.c.fixed` | `https://raw.githubusercontent.com/irontec/sngrep/d49c96c99bfff47b41c547113cb3a39dfb9b8717/src/sip.c` | `8c1a6e151f6570e28cc4e2053a6470379b2563271032c0e055d81460e082c9a6` |
| `pins/sip.h.vuln` | `https://raw.githubusercontent.com/irontec/sngrep/v1.9.0/src/sip.h` | `131d8d612fc4ffc42c05208a5c7b7968168f12592da787ce9b0bc54fae7c03b9` |
| `pins/packet.h.vuln` | `https://raw.githubusercontent.com/irontec/sngrep/v1.9.0/src/packet.h` | `6732959b326327311466a7cf371ec115ce1b85d915bc65959917e3bf6cf470d0` |

Claim and fix sources: `https://cveawg.mitre.org/api/cve/CVE-2026-121943`,
`https://github.com/irontec/sngrep/issues/589`, PR
`https://github.com/irontec/sngrep/pull/591` (diff read via
`pr://irontec/sngrep/591/diff/all`), PR metadata
`https://api.github.com/repos/irontec/sngrep/pulls/591`. The HackMD exploit
link tagged in the CVE record returned 403; the guessed VulnCheck title URL
returned 404. Both negatives are preserved in the brief.

## Harness

- `gen_sink.py` SHA-256 `ad4e2cc749e59809948d7b53b7fe78ac9d0012232327ab62d868098c1ca06d16`
  at staging. It asserts raw pinned lines 320/327/331/332/338 before copying
  raw lines 316-341 into `h/sink_vuln.cpp` and `h/sink_fixed.cpp` with
  `#line 316 "src/sip.c"`. Slices: vuln prefix
  `a0911b813f6dbe9c`, fixed `fef7b9b29f728c65` (first 16 hex of SHA-256).
- `run-all.sh` SHA-256 `a4ebf8f62e9b8f4db2d4346911a059f51dc16231595b3409e016b71b03a9b819`
  at staging. It verifies four pin hashes, regenerates both TUs, re-asserts
  the verbatim slices, builds GCC and clang ASan plus a GCC plain binary and
  runs four vectors (10240 attack, 10239 safe, 10241 guard, plain attack).
  Result at 23:15Z: `RESULT PASS=13 FAIL=0`, rc 0.
- Only frontier-authored scaffolding: types (`packet_t`), `packet_payload()`,
  `packet_payloadlen()`, `calls` regex global, `VALIDATE_NOT_SIP`, `main()`,
  local `malloc`'d source buffer. The regex pattern/flags come from raw pinned
  lines 174/201. No full sngrep build, libpcap, pcap file, socket or wire
  input. No chosen-byte readback or live adjacent object.
- Toolchain: GCC 13.3.0 (`gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`) and
  Ubuntu clang 18.1.3, both `-g -O1 -fsanitize=address -fno-omit-frame-pointer`.
  Plain build `gcc -g -O1`. Host: Linux x86-64, glibc. Addresses, PIDs and
  BuildIDs in `runs/*.out` vary per run and are not claims.

## Observed traces (verbatim)

- `runs/asan-vuln-10240.out`: `READ of size 10241`, frame
  `sip_validate_packet(packet*) src/sip.c:338`, object `[128, 10368)
  'payload' (line 320) <== Memory access at offset 10368 overflows this
  variable`; rc 1.
- `runs/clang-asan-vuln-10240.out`: same `stack-buffer-overflow` at
  `src/sip.c:338`; rc 1.
- `runs/asan-fixed-10240.out`, `runs/asan-vuln-10239-safe.out`,
  `runs/asan-vuln-10241-guard.out`: rc 0, no ASan.
- `runs/plain-vuln-10240.out`: rc 0, `SIP_VALIDATE_RC=0` (rung 1/2 negative).

## Negative / boundary record

- ASan's 10241-byte read is the `strlen` scan length, not a 10241-byte memcpy
  and not a chosen byte. The single byte overflowed is the missing terminator.
- The fixed pin keeps the `> MAX_SIP_PAYLOAD` guard; 10241 is rejected on both
  pins. That guard control is asserted independently of the +1 buffer.
- `sip_check_packet` and the INVITE `strdup()` sink named by the issue are not
  harnessed; do not claim they were reproduced locally.
- Rung 3 only. Rung 1/2/4/5 NOT CLAIMED.
