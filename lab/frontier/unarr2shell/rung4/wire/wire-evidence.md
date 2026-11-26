# unarr2shell wire-to-sink replay — 2026-11-26T16:26:23Z

Loopback-only synthetic consumer: 127.0.0.1 TCP body ->
ar_open_memory -> ar_open_tar_archive -> ar_parse_entry ->
ar_entry_get_name. No real application caller; no external target.
Libraries: build/vuln/libunarr.a (verbatim v1.1.0) and
build/fixed/libunarr.a (synthetic +1-byte control),
both built by harness/run-all.sh with ASan.

## Observed
[vuln-attack] rc=1
  WIRE_BYTES=1536
  ==4186769==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x512000000141 at pc 0x7702678f6260 bp 0x7ffde6e62350 sp 0x7ffde6e61af8
  WRITE of size 101 at 0x512000000141 thread T0
[vuln-safe-name] rc=0
  WIRE_BYTES=1536
  entry name: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[vuln-safe-prefix] rc=0
  WIRE_BYTES=1536
  entry name: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[fixed-attack] rc=0
  WIRE_BYTES=1536
  entry name: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Interpretation: crafted tar bytes delivered on loopback reach the same
tar_get_name overflow (WRITE of size 101) through the public API; safe
inputs and the synthetic fixed build stay clean. This is rung-4 wire
mechanics with a synthetic consumer: it establishes neither a real
network-facing caller nor rung 5. Grade unchanged: rung 3 verbatim /
rung 4 PARTIAL fixed NUL.
