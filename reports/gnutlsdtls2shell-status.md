# gnutlsdtls2shell — status (STAGED 2026-11-26 W286)

STAGED by frontier W286; brief `reports/frontier-gnutlsdtls2shell.md`, charter
`charters/gnutlsdtls2shell.md`, seed wall
`.mishe-tauftauf/walls/gnutlsdtls2shell.md`, harness
`lab/frontier/gnutlsdtls2shell/` (`PROVENANCE.md` has hashes, traces and
preserved negatives). Operator admission and independent witness replay are
owed. Two-pane window 195 is live on the inner socket; registry has unique
target names.

## Claim and pins

- CVE-2026-33846 / GNUTLS-SA-2026-04-29-1, High heap overwrite, fixed in
  GnuTLS 3.8.13. Fix commit
  `65ab33fa54e34fba69d793735b7df3d383d1ff78` adds 20 lines to `lib/buffers.c`,
  enforcing consistent `message_length`, a `start_offset + data.length` bound
  and a `max_length` bound before the merge memcpy.
- Pinned `gnutls-3.8.12.tar.xz` SHA-256
  `a7b341421bfd459acf7a374ca4af3b9e06608dcd7bd792b2bf470bea012b8e51`;
  `gnutls-3.8.13.tar.xz` SHA-256
  `ffed8ec1bf09c2426d4f14aae377de4753b53e537d685e604e99a8b16ca9c97e`;
  `nettle-3.10.tar.gz` SHA-256
  `b4c518adb174e484cb4acea54118f02380c7133771e7e9beb98a0787194ee47c`.
  Host nettle 3.9.1 is too old and host libunistring-dev is absent; both pinned
  builds use locally built nettle 3.10 and `--with-included-unistring`, and
  runtime needs `LD_LIBRARY_PATH=<lab>/opt/lib64`.

## Observed

- Vulnerable 3.8.12, GCC ASan, four loopback UDP ClientHello fragments with
  conflicting `message_length`: `ERROR: AddressSanitizer: heap-buffer-overflow`,
  `WRITE of size 1475`, sink `merge_handshake_packet` at
  `../../src/gnutls-3.8.12/lib/buffers.c:1035`, called from
  `_gnutls_parse_record_buffered_msgs` at :1320; address is 0 bytes after a
  2048-byte region allocated through `gnutls_realloc_fast` /
  `buffer_resize_reclaim` (`lib/str.c:187`). Attacker filler is the byte 'E'.
  `evidence/attack-asan-3.8.12.out`.
- Safe-input control on the same vulnerable build (`SAFE=1`, consistent
  `message_length=3000`): no ASan report; handshake returns -319 (timeout).
  `evidence/safe-asan-3.8.12.out`.
- Fixed 3.8.13 with the identical attack input: no ASan report; handshake
  returns -9 (`Error decoding the received TLS packet.`), showing the new
  length checks reject the fragments. `evidence/attack-asan-3.8.13.out`.
- `sh lab/frontier/gnutlsdtls2shell/run-all.sh` at 20:05Z: `RESULT PASS=12
  FAIL=0`, runner rc 0; all three tarball hashes re-asserted.

## Grade and negatives

Rung 3 ASan-confirmed heap overwrite through the shipped library API, with
attacker-controlled bytes and a fixed-version control. Rung 4 NOT CLAIMED:
ASan poisons the bytes past the allocation; no plain-build adjacent live
object, pointer, command buffer or socket has been shown to change at a chosen
offset. Rung 5 NOT CLAIMED. Negatives preserved: initial `make -C lib` failure
without `make -C gl` (included unistring), runtime hogweed symbol mismatch
without `LD_LIBRARY_PATH`, fixed-build rejection, safe-input clean result.

## Next action

Witness clean-archive replay first. Then a plain-build neighbouring-allocation
experiment for rung 4: observe whether 'E' bytes land in a live object at a
chosen offset, then try a benign marker. No external target; loopback only.
