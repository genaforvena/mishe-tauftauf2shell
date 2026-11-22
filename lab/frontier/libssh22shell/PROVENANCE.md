# Provenance — libssh22shell (CVE-2026-66035)

All source was fetched read-only from public GitHub during W119 provisioning.
No external host was probed; no runtime instance was started.

## Pins

| role | commit | file | SHA256 |
| --- | --- | --- | --- |
| vulnerable | `edec1cce27a309399a9d174b73fef9b997148fbb` (parent of fix) | `pins/transport-vuln.c` | `54af80fc7be8efc8639604f69f5597e83daea7168a197599732dd5b7a158ecb7` |
| fixed | `42e33d81577ed4b95d4b4f6f845e5ee8efe5eeb4` | `pins/transport-fixed.c` | `cfeb9c18d84da3c1fbc215aaaf2e6df44b7ee85d3f85c466f42b5d7a87ad947b` |

Fetch commands:

```
curl -fsSL -o pins/transport-vuln.c \
  https://raw.githubusercontent.com/libssh2/libssh2/edec1cce27a309399a9d174b73fef9b997148fbb/src/transport.c
curl -fsSL -o pins/transport-fixed.c \
  https://raw.githubusercontent.com/libssh2/libssh2/42e33d81577ed4b95d4b4f6f845e5ee8efe5eeb4/src/transport.c
```

`pins/PIN_HASHES.txt` holds both hashes in `sha256sum --check` form and is
verified at the top of `harness/run.sh`. The fix commit's signed payload and
PR #2198 were also read; see `reports/frontier-libssh22shell.md` §1 for the
GHSA-6c79-444r-wx26 / GHSA-v6rf-8q4r-r495 discrepancy.

## Harness inventory

- `harness/gen_fn.py` — extracts `transport_fullpacket()` verbatim from a pinned
  `transport.c` into `transport_fn.inc` (180 lines vulnerable, 185 fixed). No
  edits to the function text.
- `harness/harness.c` — local only: minimal `LIBSSH2_SESSION`,
  `struct transportpacket`, `struct mac_method`, `struct crypt_method`,
  `struct comp_method`; the pinned names for error codes, states, macros and
  allocators; stubs for `transport_decrypt` (fills the decrypted first block
  with a chosen byte sequence), `ssh2_timingsafe_bcmp` (MAC confirms), the MAC
  hash, and `ssh2_packet_add` (saves the written buffer for readback); and the
  driver that sets `total_num`, `mac_len`, `blocksize` and calls the verbatim
  function with `encrypted=1`.
- `harness/normalize.py` — strips PID, addresses, paths, BuildId and allocator
  shadow-byte rows so logs hash identically across builds and trees.
- `harness/run.sh` — builds gcc and clang ASan plus gcc plain on both pins,
  asserts 17 conditions, writes nine normalized logs and `EVIDENCE_HASHES.txt`.

Not included: any libssh2 library build, cipher implementation, MAC key,
session handshake, network socket or daemon. The decrypt and MAC steps are
stubs; the arithmetic, allocation and overflowing copy are the pinned bytes.

## Replay

```
cd lab/frontier/libssh22shell && bash harness/run.sh
```

Expected: `TOTAL 17 PASS / 0 FAIL`, rc 0, nine hashes in
`EVIDENCE_HASHES.txt` (normalized logs in `evidence/`). Verified twice in-tree during W119 with
byte-identical hashes.
