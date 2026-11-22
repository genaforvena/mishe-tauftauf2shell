# Frontier brief: baresip/re `websock_decode()` wrapped length check — GHSA-hvxv-v2gp-v93h / CVE-2026-50161 (baresip2shell)

Status W128 (2026-11-22): STAGED. Screened in and measured at rung 3
(ASan-confirmed out-of-bounds access in a verbatim pinned function) plus a
scoped rung 4 (attacker-chosen 4-byte XOR pattern lands on adjacent heap bytes
past the payload region, direct-call/stub scope). Duplicate check before
provisioning: no prior `reports/frontier-*baresip*`, no baresip/re window,
charter or mind on the tape, and neither "baresip" nor "re" appears in the
do-not-duplicate list in `walls/frontier.md`. Distinct from the staged
sofiasip2shell `ws_read_frame` bug: different project, different function,
different guard (64-bit unsigned wrap on the masked-frame length check versus
an over-long unmask over datalen). Ranked above PJSIP DNS (larger parser),
Ettercap (MITM client, not an X2Shell server), and the held gdbserver claim
(no fix bytes used here); Ruby, Node, PostgreSQL, C-Kermit and Netty are owned
or screened out. The operator owns final admission; wake units and full-flag
sync stay with the person.

## 1. Verified ground truth

- Claim: GHSA-hvxv-v2gp-v93h, "Integer overflow in `websock_decode()` masked
  frame length check leads to heap buffer overflow", published 2026-05-28 by
  `sreimers`; Critical; CWE-190 (integer wraparound) and CWE-787 (out-of-bounds
  write); CVE-2026-50161. Affected `<= 4.8.0`; patched `>= v4.8.1`.
- Claim source read (read-only provisioning, no external probe):
  `https://github.com/baresip/re/security/advisories/GHSA-hvxv-v2gp-v93h`.
  Source pins fetched read-only from `https://github.com/baresip/re.git`:
  `v4.8.0` = `7ace643f`, `v4.8.1` = `89aed31f`; fix commit
  `718b926` (PR #1584) is the only `websock.c` change between the tags.
- Primitive claimed: for a masked client-to-server frame with the 64-bit
  extended length encoding, `hdr->len` is `uint64_t` and the guard
  `mbuf_get_left(mb) < (4 + hdr->len)` is evaluated with unsigned wraparound.
  For `hdr->len = 0xFFFFFFFFFFFFFFFC`, `4 + len` wraps to 0 and the guard
  always passes; the XOR unmask loop then writes past the buffer with an
  attacker-chosen 4-byte repeating key. The advisory's example is a 14-byte
  frame: `0x82`, `0xFF`, eight length bytes ending `0xFC`, four mask bytes.
- Reachability claim (unverified here): any application using libre's
  `websock_accept()` / `websock_accept_proto()` as a WebSocket server,
  including baresip and other SIP/VoIP applications. `recv_handler()` checks
  `conn->active == hdr.mask`; for a server connection `conn->active` is false,
  so the masked path is claimed to always be taken for valid client frames.
  Pre-authentication after the HTTP upgrade; the stated impact is heap
  corruption and denial of service, not RCE.

## 2. Source-bound mechanism and fix

Vulnerable pin `7ace643f`, `src/websock/websock.c` inside `websock_decode()`:

```c
if (hdr->mask) {

    if (mbuf_get_left(mb) < (4 + hdr->len))
        return ENODATA;

    hdr->mkey[0] = mbuf_read_u8(mb);
    ...
    for (i=0, p=mbuf_buf(mb); i<hdr->len; i++)
        p[i] = p[i] ^ hdr->mkey[i%4];
}
```

`mbuf_get_left()` is `size_t` and `hdr->len` is `uint64_t`; on this 64-bit
host `0xFFFFFFFFFFFFFFFC + 4 == 0`, so `left < 0` is false. The 4 mask bytes
are consumed and the unmask loop runs with `size_t i` up to a value near
2^64. The written value is the pre-existing heap byte XOR the chosen key,
i.e. a chosen *pattern* applied to a chosen region, not an arbitrary absolute
value unless the original bytes are known.

Fixed pin `89aed31f` adds the two-line guard from commit `718b926`:

```c
if (hdr->len > SIZE_MAX - 4 ||
    mbuf_get_left(mb) < (4 + hdr->len))
    return ENODATA;
```

The saved fix diff is `lab/frontier/baresip2shell/src/fix-718b926.patch`
(sha256 `b579bb5e...`).

## 3. Local reproduction — observed bytes

Harness `lab/frontier/baresip2shell/harness/run.sh`; full pin hashes, toolchain
and instrumentation boundary in `lab/frontier/baresip2shell/PROVENANCE.md`.
The 54-line vulnerable and 55-line fixed `websock_decode()` slices are
re-extracted from saved pinned bytes and SHA-256-asserted on every run.

- **43 PASS / 0 FAIL twice**, gcc 13.3.0 and clang 18.1.3; path-independent
  normalized content hash
  `f0eb31725d4125505767c80c12e1d31cdc6edefcbb14950264ba23f4f123f483`.
- Vulnerable pin, crafted frame printed before the call:
  `CRAFT_B0=82 CRAFT_B1=ff MASKBIT=1 LENBYTES=fffffffffffffffc KEY=b4b4b4b4`.
  Both compilers report `ERROR: AddressSanitizer: heap-buffer-overflow`,
  `READ of size 1`, `0 bytes after 30-byte region`, top frame
  `websock_decode`. The read is the load half of `p[i] = p[i] ^ mkey[i%4]`;
  ASan traps there before the store.
- Plain guard-page run on the vulnerable pin (no ASan, PROT_NONE page after a
  32-byte sentinel region): `REGION_BYTES=30 PAYLOAD_BYTES=16
  SENTINEL_BYTES=32 KEY=0xb4`, pre-sentinel all `0xEE`,
  `PLAIN_FIRST_OOB_OFFSET=12`, `PLAIN_FAULT_OFFSET=44`, and
  `PLAIN_ADJACENT=5a5a...` (32 bytes), i.e. 32 adjacent bytes were changed
  from `0xEE` to the chosen `0x5A` (`0xEE ^ 0xB4`) past the 30-byte region.
  This is the observed out-of-bounds **write**.
- Fixed pin on the same attack frame: `RC=61` (`ENODATA`),
  `HDR_LEN=0xfffffffffffffffc`, `PAYLOAD_FIRST=00`, `MKEY=00000000`,
  `CONSUMED=10`, no ASan report — it rejects before consuming the key or
  writing anything. A safe 8-byte masked frame is clean on both pins
  (`RC=0`, payload bytes `b4`), fixed pin likewise.

## 4. Honest grade and what is *not* established

- **Rung 1 (reproducible trigger)**: yes, deterministic direct call with a
  synthesised 14-byte frame.
- **Rung 2 (state failure)**: yes, the pinned guard passes with a wrapped
  `4 + len == 0` while the loop bound remains near 2^64; the fixed pin rejects
  the same bytes with no writes.
- **Rung 3 (confirmed corruption)**: yes, ASan heap-buffer-overflow in the
  verbatim vulnerable function on two compilers, with clean fixed pin and
  safe-frame control. The ASan report names the read half of the read-modify-
  write; the store half is proven by the plain readback.
- **Rung 4 (scoped)**: yes, in the direct-call/stub sense — the attacker
  chooses the 4-byte XOR key and therefore the pattern applied to the 32
  adjacent bytes past the payload region. This is **not** a real libre build,
  `websock_accept()` server, HTTP upgrade, wire frame, natural `mbuf`
  allocator layout, adjacent heap object, pointer control, benign marker or
  command. The loop would run ~2^64 times in a real build; ASan and the guard
  page stop it at the first inaccessible byte, so the neat 32-byte overwrite
  is a harness artefact, not a claimed real-world overwrite length.
- **Rung 5**: not attempted and not implied. No listener, no command, no
  observed side effect. The advisory's pre-auth reachability and DoS impact
  stay claims.

Known limits: stubs reproduce only the `mbuf_*` helpers the pinned function
calls, not libre's real allocator/refcounting; the frame is synthesised
directly rather than parsed from a TCP stream; the advisory's "14-byte frame"
is the minimum header, while this harness adds 16 payload bytes so the first
ASan trap is one byte past a 30-byte region rather than at an empty buffer.

## 5. Cheapest next rung-moving experiment

Build libre `v4.8.0` with ASan, start `websock_accept()` on a plant-started
127.0.0.1 listener, complete the HTTP WebSocket upgrade, then send the exact
14-byte masked binary frame (`82 ff` + eight length bytes ending `fc` + four
mask bytes). Expect the same ASan report in the real `websock_decode()`.
Repeat with `v4.8.1` (expect `ENODATA`, no write) and with a short masked frame
(expect clean unmask). If a plain build survives long enough, inspect the
first heap chunk past the `mbuf` payload to see how far the repeating XOR key
propagates before the process dies. All loopback; no external system.

## 6. Disposition

Staged W128 at 23:1xZ: charter `.mishe-tauftauf/charters/baresip2shell.md`,
seed wall `.mishe-tauftauf/walls/baresip2shell.md`, live two-pane inner tmux
window, registry entry, operator and witness DMs, and a scoped commit
covering this brief, the pinned source snapshots and the harness. The window
will already exist; do not create another. Admission is the operator's;
until then this is a staged candidate, not an admitted target.
