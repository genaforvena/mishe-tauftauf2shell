# Frontier brief: libssh2 — CVE-2026-66035 (libssh22shell)

Status W119 (2026-11-22): screened in, driven locally to rung 3/4 and staged as
`libssh22shell`. Duplicate check before provisioning: no prior
`reports/frontier-*libssh*`, no libssh2 window, charter or mind on the tape;
the only libssh2 mentions in the repo were unrelated dependency trees. Admission
remains the operator's call; wake units and full-flag sync stay with the person.

## 1. Verified ground truth

- Claim: GHSA-v6rf-8q4r-r495 / CVE-2026-66035, "libssh2 through 1.11.1, fixed
  in commit `42e33d8`, contains a pre-authentication heap buffer overflow that
  lets a malicious SSH server corrupt heap metadata in any connecting client by
  sending a packet with `packet_length` smaller than the cipher's block size
  during Encrypt-then-MAC (ETM) cipher negotiation" (CWE-122). Advisory severity
  High / CVSS v4 7.7 (`AV:N/AC:H/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H`). NVD record
  2026-07-24; GitHub Advisory Database entry Unreviewed.
- Sources read (read-only provisioning; no probe of any external system):
  `https://github.com/advisories/GHSA-v6rf-8q4r-r495`, PR
  `https://github.com/libssh2/libssh2/pull/2198`, fix commit
  `https://github.com/libssh2/libssh2/commit/42e33d81577ed4b95d4b4f6f845e5ee8efe5eeb4`
  and its `.patch`, and both pinned raw `src/transport.c` blobs.
- Affected: through 1.11.1 (advisory prose). Fixed: commit `42e33d8`
  (2026-07-03, verified signed); the advisory's Patched versions field is
  Unknown, so no fixed release number is asserted. Pin pair used here:
  vulnerable parent `edec1cce27a309399a9d174b73fef9b997148fbb`, fixed
  `42e33d81577ed4b95d4b4f6f845e5ee8efe5eeb4`.
- Provenance discrepancy preserved, not smoothed over: the fix commit message
  says `Fixes GHSA-6c79-444r-wx26`, which currently resolves HTTP 404 on the
  GitHub advisory site; the public advisory that cites this commit is
  `GHSA-v6rf-8q4r-r495`. Both identifiers belong to the same fix; the mismatch
  is a claim-source fact, not a local observation.
- The advisory also claims 32-bit glibc tcache bin confusion, overlapping live
  objects and a function-pointer overwrite during the handshake. Those are
  **claims**, not local observations: this lab ran 64-bit glibc with ASan.

## 2. Source-bound mechanism and fix

In `libssh2/src/transport.c`, `transport_fullpacket()` handles an incoming
ETM-encrypted packet. Vulnerable pin at lines 235-263:

1. `first_block` (`unsigned char first_block[MAX_BLOCKSIZE]`) is decrypted from
   the first `blocksize` bytes of the attacker-supplied payload.
2. `decrypt_size = p->total_num - mac_len - 4` (line 248, `ssize_t`), where
   `p->total_num` is the attacker-controlled wire packet length.
3. `decrypt_buffer = SSH2_ALLOC(session, decrypt_size)` (line 249) allocates
   exactly that many bytes.
4. `if(blocksize > 1) memcpy(decrypt_buffer, first_block + 1, blocksize - 1)`
   (line 263) writes `blocksize - 1` bytes unconditionally.

For `total_num < mac_len + 4 + blocksize`, the allocation is smaller than the
copy, so the fixed-size copy overruns it. With `total_num < mac_len + 4` the
`ssize_t` size is negative and converts to a huge `size_t`, a distinct failure
mode not exercised here. The copied bytes come from the decrypted first block,
so the overflow content is attacker-influenced; `p->padding_length` (the first
byte of that block) must be at most `packet_length - 1` to reach the memcpy.

Upstream fix `42e33d8` inserts six lines before `first_block[0] = 0`:

```c
if(p->total_num < mac_len + 4 + (size_t)blocksize) {
    SSH2_SAFEFREE(session, p->payload);
    return LIBSSH2_ERROR_DECRYPT;
}
decrypt_size = (ssize_t)(p->total_num - mac_len - 4);
```

and deletes the later `decrypt_size` assignment. Both markers were checked in
the pinned blobs: the guard is absent from the vulnerable pin and present in
the fixed pin.

## 3. Measured evidence (this lab)

`lab/frontier/libssh22shell/harness/` extracts `transport_fullpacket()`
**verbatim** from each pinned `transport.c` (180 lines vulnerable, 185 fixed)
with `gen_fn.py`; only the minimal struct/macro stubs, the MAC-confirm stub,
the first-block stub and the driver are local. Full inventory in
`PROVENANCE.md`. `bash harness/run.sh`: rc 0, **17 PASS / 0 FAIL**, nine
normalized logs.


- Vulnerable gcc and clang ASan, `TOTAL_NUM=28`, `mac_len=20`, `blocksize=16`
  (so `decrypt_size=4`, copy 15): `heap-buffer-overflow`, `WRITE of size 15`,
  0 bytes after a 4-byte region, top frame `transport_fullpacket` in the
  verbatim pinned function. Nonzero rc.
- Plain readback, chosen first-block base `0x41`:
  `readback=4142434445464748494a4b4c4d4e4f…` — 15 chosen bytes at offsets
  0..14 of the sink, 11 of them past its 4-byte end. Base `0x5a` gives
  `5a5b5c5d5e5f606162636465666768…`, so the bytes are chosen, not incidental.
- Fixed pin, same packet: `rc=-18` (`LIBSSH2_ERROR_DECRYPT`) with the guard
  firing; ASan clean, no readback. Fixed plain agrees.
- Safe-input control, `TOTAL_NUM=64` (`decrypt_size=40`, copy fits): clean under
  ASan on both pins.
- Nine normalized hashes in `EVIDENCE_HASHES.txt`; two in-tree replays and a
  clean `git archive 9795ecf` replay produced byte-identical logs (17/17 PASS
  in the archive too). Normalization strips PID, paths, addresses, BuildId and
  allocator shadow-byte rows.

## 4. Rung-4 feasibility and honest ceiling

Rung 1/2: deterministic trigger and observed size-accounting failure at the
verbatim pinned function. Rung 3: natural ASan corruption there. Rung 4: 15
attacker-chosen bytes land at chosen offsets relative to an undersized heap
sink, at **direct-call/stub scope only**. No libssh2 process, SSH handshake,
network wire, allocator grooming, pointer control, command execution or rung 5.
Copy content is constrained by the decrypted-first-block stub; arbitrary bytes
at arbitrary heap offsets are NOT established.

The victim is a **connecting client** fed by a malicious server, not a
web-facing server. The plant has admitted client-side corrupted consumers
before, but the operator should weigh that explicitly: this is an X2Shell-class
memory-corruption primitive, not an X2Shell wire service. The advisory's
32-bit-glibc heap-metadata/tcache/function-pointer story is a plausible reason
to rank this highly, but it is unverified here and the 64-bit allocator layout
differs.

Tractability: high for this lab's pattern — two blobs, one 180-line C function,
no build system, no daemon. It outranks the remaining queue: FRR's
CVE-2026-129217 is an OOB read, llama.cpp CVE-2026-118375 needs RDMA, and
Libreswan CVE-2026-94453 needs non-default `listen-tcp` plus a UAF.

## 5. Cheapest next experiment to move up a rung

Build pinned libssh2 1.11.1 with ASan and drive a real `libssh2_session_handshake()`
against a plant-started 127.0.0.1 fake SSH server that completes KEX, selects
an ETM cipher (`aes128-ctr` + `hmac-sha1-etm@openssh.com`) and then sends one
short encrypted packet with `total_num=28` and a valid ETM MAC. Decisive
controls: the same handshake with `total_num>=40` stays clean; the patched
commit rejects with `LIBSSH2_ERROR_DECRYPT`; safe input leaves the client alive.
A successful replay upgrades rung 4 from direct-call to a live client process;
it still needs chosen-pointer or command side effects for rung 5.

## 6. Candidates parked / screened this wake

- Witness #1556 (inetutils2shell W1 wire) was grade-unchanged; no frontier
  action. The five fresh `failed-m2shell-wake-*` REDs were dispositioned by the
  operator at 18:40Z as engine-cap saturation, owner=person.
- Web-screened and rejected: SonicOS SSL-VPN CVE-2026-82308 (proprietary, no
  source), wolfSSL CVE-2026-6679 (already owned as `wolfssl2shell`), FreeRDP
  CVE-2026-64620, accel-ppp CVE-2026-123205, C-Kermit CVE-2026-129126, iperf3
  CVE-2026-101283, Netty CVE-2026-116539 (all already owned), TDS prelogin
  CVE-2026-119923 (MS SQL screened out), NoMachine CVE-2026-92208 (screened out).
- FRRouting CVE-2026-129217, llama.cpp CVE-2026-118375 and Libreswan
  CVE-2026-94453 remain queued below this find, unchanged.
- Do not duplicate the admitted list in `walls/frontier.md`; NGINX/Node belong
  to other minds.
