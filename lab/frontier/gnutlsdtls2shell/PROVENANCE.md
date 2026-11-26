# PROVENANCE — gnutlsdtls2shell

All work is loopback-only. No external target was probed. Advisory and source
pages were fetched read-only as provisioning.

## Pinned inputs (fetched 2026-11-26, hashed locally)

| artifact | URL | SHA-256 |
| --- | --- | --- |
| gnutls-3.8.12.tar.xz | https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/gnutls-3.8.12.tar.xz | a7b341421bfd459acf7a374ca4af3b9e06608dcd7bd792b2bf470bea012b8e51 |
| gnutls-3.8.13.tar.xz | https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/gnutls-3.8.13.tar.xz | ffed8ec1bf09c2426d4f14aae377de4753b53e537d685e604e99a8b16ca9c97e |
| nettle-3.10.tar.gz | https://ftp.gnu.org/gnu/nettle/nettle-3.10.tar.gz | b4c518adb174e484cb4acea54118f02380c7133771e7e9beb98a0787194ee47c |

Fix commit read from `https://gitlab.com/gnutls/gnutls/-/commit/65ab33fa54e34fba69d793735b7df3d383d1ff78.patch`
(20 added lines in `lib/buffers.c`, no other files). Advisory:
`https://www.gnutls.org/security-new.html` entry GNUTLS-SA-2026-04-29-1;
CVE record `https://cveawg.mitre.org/api/cve/CVE-2026-33846`; reporter PoC and
claimed ASan trace at `https://gitlab.com/gnutls/gnutls/-/issues/1816`.

Host nettle is 3.9.1 (below the 3.10 configure minimum), so nettle 3.10 was
built into `opt/` with prefix `/home/mesh-home/mishe-tauftauf2shell/lab/frontier/gnutlsdtls2shell/opt`.
Both GnuTLS trees were configured with `--with-included-unistring` (host lacks
libunistring-dev), `--disable-doc --disable-guile --disable-nls --without-tpm
--without-tpm2 --disable-full-test-suite`, `CFLAGS='-fsanitize=address -g -O1
-fno-omit-frame-pointer'`, `LDFLAGS='-fsanitize=address'`. `make -C gl` must
precede `make -C lib` because included unistring supplies `../gl/libgnu.la`.
Runtime needs `LD_LIBRARY_PATH=<lab>/opt/lib64` so the pinned hogweed 3.10 is
loaded instead of the system 3.9.1 (otherwise `nettle_rsa_oaep_sha384_decrypt`
symbol lookup fails). Both failures and their fixes are preserved here.

## Local PoC

`poc_dtls_fragment_overflow.c` is a loopback DTLS 1.2 server with a
programmatically generated ECDSA self-signed cert. It receives four UDP
ClientHello fragments from the same process on 127.0.0.1:4433 and loops
`gnutls_handshake()` over `GNUTLS_E_AGAIN`. Fragment 1 claims `message_length=50`
(creating a 2048-byte MIN_CHUNK reassembly buffer); fragments 2-4 claim 3000
with offsets 0/40/1500 and lengths 48/1475/1475. `SAFE=1` makes fragment 1
also claim 3000, keeping `message_length` consistent: the safe-input control.

## Observations

- `evidence/attack-asan-3.8.12.out` (2026-11-26 ~20:02Z): GCC ASan
  `heap-buffer-overflow`, `WRITE of size 1475`, sink
  `merge_handshake_packet ../../src/gnutls-3.8.12/lib/buffers.c:1035`, called
  from `_gnutls_parse_record_buffered_msgs` at buffers.c:1320 and
  `_gnutls_handshake_io_recv_int` at :1414. Address is 0 bytes after a
  2048-byte region allocated via `gnutls_realloc_fast` / `buffer_resize_reclaim`
  (`lib/str.c:187`) from `gnutls_buffer_append_data` (`lib/str.c:116`).
  Attacker filler byte is 'E'. This reproduces the advisory claim on the
  unmodified pinned vulnerable release, not merely on a synthetic consumer.
- `evidence/safe-asan-3.8.12.out`: SAFE=1 on the same vulnerable build gives no
  ASan report; handshake returns -319 (timeout) after reassembling a valid
  fragmented ClientHello. The overflow is specifically the length mismatch.
- Fixed-build control: see `evidence/attack-asan-3.8.13.out` and `run-all.sh`
  output below.

## Grade

Rung 3 ASan-confirmed heap overwrite through the shipped library API. Rung 4 is
NOT CLAIMED: the chosen 'E' bytes land in ASan-poisoned space, and no adjacent
live object, pointer, command buffer or socket has been shown to change in a
plain build. Rung 5 is NOT CLAIMED.
