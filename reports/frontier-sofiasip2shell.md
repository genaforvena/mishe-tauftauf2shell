# Frontier brief: sofia-sip `ws_read_frame()` unmask over-run — GHSA-whfw-c3jj-99rp / CVE-2026-116791 (sofiasip2shell)

Status W126 (2026-11-22): screened in and measured at rung 3 (ASan-confirmed
heap out-of-bounds access in a verbatim pinned function) plus a scoped rung 4
(attacker-chosen mask-key XOR bytes at chosen offsets past a 64-byte
`bbuffer`, direct-call/stub scope). Duplicate check before provisioning: no
prior `reports/frontier-*sofia*`, no sofia-sip window/charter/mind on the tape,
and sofia-sip is absent from the do-not-duplicate list in `walls/frontier.md`.
The list contains FreeSWITCH, but that mind owns `mod_xml_rpc`'s separate
`src/mod/xml_int/mod_xml_rpc/ws.c` under CVE-2026-116785, fixed in 1.11.2; this
candidate is the separate `freeswitch/sofia-sip` library with CVE-2026-116791,
fixed in 1.13.18. The previously declined SIP-facing FreeSWITCH advisory
GHSA-f73w-xph4-pjp3 is a third, distinct claim. Operator owns final admission;
wake units and full-flag sync stay with the person.

## 1. Verified ground truth

- Claim: GHSA-whfw-c3jj-99rp, "Pre-authentication heap out-of-bounds writes in
  sofia-sip WebSocket parsing", CVE-2026-116791, published 2026-10-28 by
  GitHub. Severity HIGH, CVSS 3.1 8.2,
  `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`, CWE-122 and CWE-787. Credit Hyunwoo
  Kim. **Network, no privileges, no user interaction**; the advisory itself
  states RCE has *not* been demonstrated.
- Claim source read (read-only provisioning, no external probe):
  `https://github.com/freeswitch/sofia-sip/security/advisories/GHSA-whfw-c3jj-99rp`.
  Source pins fetched read-only from `https://github.com/freeswitch/sofia-sip.git`
  (`git ls-remote --tags` and clone): `v1.13.17` = `6198851a` (2023-11-07),
  `v1.13.18` = `ad36ac8f` (2026-08-04).
- Affected / patched fields: advisory `<= 1.13.17` affected, `>= 1.13.18`
  patched. Both tags are visible upstream and their `ws.c`/`ws.h` diff is the
  fix; no unreleased commit assumption is needed.
- Primitive claimed: `ws_read_frame()` unmasks an inbound frame by iterating
  `wsh->datalen`, which counts the WebSocket header *and* payload, while
  indexing `wsh->body`, which holds payload bytes only. A frame whose declared
  length fills the body buffer XORs up to 14 bytes past the allocation with the
  client-supplied 4-byte mask key. Both the receive and body buffers are sized
  at exactly their usable length, so a terminating NUL also lands one byte
  past. All of this runs before SIP-layer authentication. Advisory claim: an
  attacker-chosen XOR write on the adjacent glibc chunk header, ranging from
  allocator abort to corruption of a neighbouring object; RCE remains a claim.
- Deployment claim (unverified here): a profile with `ws-binding` or
  `wss-binding`; FreeSWITCH's vanilla `internal` profile is said to enable
  both by default. No FreeSWITCH configuration was exercised in this lab.

## 2. Source-bound mechanism and fix

Vulnerable pin `6198851a`, `libsofia-sip-ua/tport/ws.c`, inside
`ws_read_frame()`:

```c
wsh->rplen = wsh->plen - need;
if (wsh->rplen) {
    memcpy(wsh->body, wsh->payload, wsh->rplen);
}
while (need) {
    ssize_t r = ws_raw_read(wsh, wsh->body + wsh->rplen, need, WS_BLOCK);
    ...
    wsh->datalen += r;
    wsh->rplen += r;
}
if (mask && maskp) {
    ssize_t i;
    for (i = 0; i < wsh->datalen; i++) {
        wsh->body[i] ^= maskp[i % 4];
    }
}
...
*(wsh->body + wsh->rplen) = '\0';
```

For a masked frame using the 64-bit length field, `datalen = 2 + 8 + 4 + plen`
and `rplen = plen`, so the loop bound exceeds the payload by exactly 14. When
`plen == bbuflen`, the loop indexes `body[bbuflen .. bbuflen+13]` and the NUL
lands at `body[bbuflen]` — 14 bytes and 1 byte past the allocation respectively.

Fixed pin `ad36ac8f` changes exactly the relevant lines:

```c
for (i = 0; i < wsh->rplen; i++) {          /* was: wsh->datalen */
    wsh->body[i] ^= maskp[i % 4];
}
```

and, in `ws_init()` and the body realloc, allocates `buflen + 1` / `bbuflen + 1`
so the terminator has a slot. The same diff also bounds the 64-bit length while
still unsigned (`len > payload_size_max` rejection) and sizes the body from
`blen + plen` instead of the overflow-prone `need + blen + rplen`; those are
hardening around the same bound, not the observed trigger.

The pinned fix diff is saved as `lab/frontier/sofiasip2shell/src/fix-1.13.18.patch`
(sha256 `b3eefca2...`).

## 3. Local reproduction — observed bytes

Harness `lab/frontier/sofiasip2shell/harness/run.sh` (details and all pin hashes
in that directory's `PROVENANCE.md`). Function under test is **verbatim**
from each pin; the rest is deterministic stubs and a scripted frame feed.

- **128 PASS / 0 FAIL, twice** (gcc + clang, two rounds, two pins, four cases
  each), rc 0. Normalized evidence hash over all `evidence/*.log`:
  `2ee5618bf4ff4df33b72c9dc1b0f027cbfca23a28b7b59cff5f1455a16ac7595`.
- Vulnerable pin, ASan, 64-byte payload into 64-byte `bbuffer`:
  `ERROR: AddressSanitizer: heap-buffer-overflow`, `READ of size 1`,
  `0 bytes after 64-byte region`, frame `ws_read_frame` at
  `fns-1.13.17.inc:185`, allocation in the driver. Unbuffered setup line
  `PRECALL PAYLOAD=64 BBUFLEN=64 MASK=415a4243` is captured before the abort.
- Fixed pin, same case: rc 0, no ASan report, `DATALEN=78 RPLEN=64` — the loop
  is bounded by `rplen` and the `+1` slot absorbs the NUL.
- Safe control (48-byte payload) on both pins: ASan clean.
- Plain-mode chosen-byte readback with a `0xEE` sentinel past the conceptual
  allocation: vulnerable pin `CHOSEN_BAD=0`, `NUL=00`, `B1=b4`, `B2=ac`,
  `B3=ad`, `B13=b4`, `TAIL=ee` — offsets 65..77 carry `0xEE ^ mask[i%4]` for
  mask `41 5a 42 43`, offset 64 carries the terminator, offset 78 is untouched
  (14-byte extent). Fixed pin `CHOSEN_BAD=1`, `B1=ee`, `TAIL=ee`: no write.

Every `fns-*.inc` is re-extracted and asserted verbatim against its pinned
source on each run before compilation; a wrong slice aborts the run.

## 4. Honest grade and what is *not* established

- **Rung 1 (reproducible trigger)**: yes, deterministic direct call.
- **Rung 2 (state failure)**: yes, `datalen=78` vs `rplen=64` state mismatch
  observed in the fixed pin's surviving output and in the plain readback.
- **Rung 3 (confirmed corruption)**: yes, ASan heap-buffer-overflow in the
  verbatim vulnerable function, with a clean fixed pin and safe control.
- **Rung 4 (scoped)**: yes, in the direct-call/stub sense — chosen mask bytes
  land at chosen offsets past a 64-byte allocation. This is **not** a natural
  heap layout, a real 64 KiB sofia-sip chunk, or an adjacent glibc chunk header;
  no neighbouring object was corrupted, no pointer was controlled, and no
  benign marker was executed. The advisory's "attacker-chosen XOR write" is
  demonstrated at the arithmetic level, not in a live allocator.
- **Rung 5**: not attempted and not implied. No sofia-sip or FreeSWITCH build,
  no WebSocket upgrade, no loopback listener, no wire input, no command. The
  advisory's RCE sentence stays a claim.

Known limits: the harness uses a 64-byte `bbuffer` rather than the real
64 KiB so the OOB fits in a short log; the XOR result depends on the bytes
already present past the allocation (`0xEE` sentinel here), so "chosen bytes"
means chosen *delta* given known heap contents; the plain mode deliberately
places the allocation inside a controlled arena, which is why an ASan redzone
cannot be used for the readback (standing negative in the wall).

## 5. Cheapest next rung-moving experiment

Build sofia-sip `v1.13.17` with ASan plus a minimal loopback `ws-binding`
listener, complete an unauthenticated WebSocket upgrade, and send one masked
BINARY frame declaring 65536 bytes (the default `bbuflen`) so the payload fills
the body buffer. That exercises the real `ws_raw_read` path and the real malloc
layout; expect an ASan report at the same loop. Then, in a non-ASan build with
a groomed adjacent chunk, read back the 14 bytes past the 64 KiB allocation to
see whether the mask delta reaches a slab/heap header or an adjacent object.
Fixed-pin (1.13.18) and short-frame controls are mandatory. This requires a
sofia-sip build environment and a local listener only; nothing off loopback.

## 6. Disposition

Staging to a dedicated `sofiasip2shell` mind and window is the intended
handoff; until that window is live and registered, this is a frontier-owned
candidate, not an admitted target.
