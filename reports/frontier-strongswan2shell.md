# Frontier brief — strongSwan2Shell (strongSwan, CVE-2026-35330)

## Verified ground truth (claims, not lab proof)

- Upstream advisory
  <https://www.strongswan.org/security/CVE-2026-35330.html>, published
  2026-04-22, read 07:55Z: a vulnerability in `libsimaka` related to processing
  certain EAP-SIM/AKA attributes "can result in an infinite loop or a
  heap-based buffer overflow and potentially remote code execution". **All
  versions since 4.3.6 are affected**; fixed in **6.0.6**. CVSS is not given
  by the advisory (UNKNOWN). Public third-party pages claim a remote exploit
  module (Exploit-DB 52587, Powder Keg Technologies) — treated as claims, not
  reproduced here.
- The advisory's own description: attribute headers are one type byte plus one
  length byte in 4-byte units; a valid length is at least 1. For variable-length
  attributes the upstream code checked remaining message bytes but not
  `length == 0`, so `hdr->length * 4 - 2` underflows `size_t`. `chunk_skip()` is
  a no-op, giving an infinite loop for `AT_PADDING`; for other types the
  wrapped length reaches `malloc()` and `memcpy()`. The advisory says RCE
  "might be possible" and does **not** claim demonstrated control flow.
- Fix commit `aa5aaebc33e0f326d8a0dbe01b236f2bfa0e6ea1` ("libsimaka: Reject
  zero-length EAP-SIM/AKA attributes", Lukas Johannes Möller, 2026-03-11)
  adds `hdr->length == 0 ||` to the guards at
  `src/libsimaka/simaka_message.c:419` (`AT_ENCR_DATA`/`AT_RAND`) and `:442`
  (`AT_PADDING`/default). Verification pins are at `6.0.5` (vulnerable) and
  `6.0.6` (fixed); hashes in `lab/frontier/strongswan2shell/PROVENANCE.md`.
- Reachability condition from the advisory: the EAP-SIM/AKA method must
  terminate on the VPN server. Clients/servers not using EAP-SIM/AKA and
  servers offloading it to RADIUS are **not** vulnerable. This is a
  configuration-dependent pre-auth IKEv2 path, not an ordinary default
  listener — a real limitation for rung-4 reachability that remains an
  external claim here.

## Source-bound mechanism

At `6.0.5`, `parse_attributes()` (`simaka_message.c:308-486`) reads a 2-byte
`attr_hdr_t` (`type`, `length`). Two branches omit the zero check:

```
if (hdr->length * 4 > in.len || in.len < 4) { ... }        /* :419, :442 */
data = chunk_create(in.ptr + 4, hdr->length * 4 - 4);      /* :423, AT_RAND */
data = chunk_create(in.ptr + 2, hdr->length * 4 - 2);      /* :446, default */
in   = chunk_skip(in, hdr->length * 4);                    /* :424/:447, no-op */
```

With `hdr->length == 0` and `size_t` 64-bit, `data.len` becomes
`0 - 4 = 18446744073709551612` (RAND) or `0 - 2 = 18446744073709551614`
(default). The special-attribute switch (`452-480`) routes non-PADDING types
to `add_attribute()` (`252-263`):

```
attr = malloc(sizeof(attr_t) + data.len);   /* :257  -> wraps to 12 or 14 */
attr->len = data.len;                       /* :258  -> OOB store of 8 bytes */
attr->type = type;
memcpy(attr->data, data.ptr, data.len);     /* :260  -> wrapped huge copy */
```

`attr_t` is `{ simaka_attribute_t type; size_t len; char data[]; }`, 16 bytes
on this host; the wrapped allocation (12/14 bytes) is smaller than the struct,
so even the field store at `:258` is out of bounds. The source pointer
`data.ptr` is attacker-supplied attribute bytes (`in.ptr + 2` or `+ 4`), so the
copy source content is chosen. `AT_ENCR_DATA` (type 130) takes the same
underflowed `:423` path but routes to `this->encr` without `add_attribute()`,
leaving `in` unchanged and causing the advisory's infinite loop. `6.0.6`
rejects all three with `invalid_length()` before any arithmetic.

## Local replay and observed rungs

Harness `lab/frontier/strongswan2shell/` extracts the three pinned ranges
verbatim under `#line`; `chunk_t`, the linked list, callbacks and the chosen
byte source are synthetic collaborators. No daemon, socket, IKE handshake,
RADIUS server or network is used. Working-tree replay at commit `cda059a`:
**54 PASS / 0 FAIL**, raw trace
`sha256=57cd8943825f35a14f45ce134f3987c489aacbd080c6249a94c9dc808f1f3d6a`.
Two clean `git archive HEAD` extractions at `cda059a` into separate absolute
directories gave the same 54 PASS / 0 FAIL and byte-identical traces.

- Rung 1 — deterministic trigger: type `AT_IDENTITY` (14) with length byte 0
  requests a `18446744073709551614`-byte copy at the pinned `:260` and leaves
  `in` unchanged (`advanced=0`); `AT_RAND` (1) requests
  `18446744073709551612`; `AT_ENCR_DATA` (130) reaches the underflow but calls
  no sink and does not advance (the infinite-loop variant). Benign length 1
  advances normally on both paths.
- Rung 2 — accounting failure: the wrapped allocation is 14 bytes (default)
  and 12 bytes (RAND), and the vulnerable build accepts the attribute
  (`reject=0`, `add_calls=1`). Both fixed branches call `invalid_length()`
  (`type=14` / `type=1`, `add_calls=0`, no `memcpy`), while still adding a
  benign length-1 attribute.
- Rung 3 — ASan confirms real heap corruption at pinned code:
  `heap-buffer-overflow`, `WRITE of size 8` with caller
  `src/libsimaka/simaka_message.c:258 in add_attribute`, inside a 14-byte
  region (default) and a 12-byte region (RAND). Benign and fixed ASan runs are
  clean. The advisory's real-daemon crash/RCE is not reproduced here.
- Rung 4 — INSTRUMENTED only, with two separately preserved outcomes. Under a
  **bounded-copy collaborator** (131072 bytes, still logging the wrapped
  requested length), chosen `0x5a` bytes are observed at offsets 16, 32, 64,
  4096 and 65536 past `attr->data` on both vulnerable paths (`match=1`).
  Under the **real host libc** with the genuine wrapped length, the copy
  faults at `src_base - 0x20` before writing: those same destination offsets
  remain `0x00` (`match=0`). No pointer, return address, heap metadata field,
  function pointer or control-flow diversion was observed or attempted; the
  guard mapping and bounded copy are instrumentation, not upstream allocator
  properties.

## Feasibility assessment

Tractable but weaker than the recent ProxySQL lead. Strengths: a small,
readable upstream fix; a deterministic one-byte trigger; two independent
underflow branches; ASan-confirmed corruption at pinned lines; explicit
affected/fixed tags; an advisory that names potential RCE. Weaknesses: rung 4
chosen-byte reach is demonstrated only under a bounded-copy collaborator, and
the real host libc's huge copy faults before writing past the allocation;
EAP-SIM/AKA must terminate locally rather than on RADIUS; no public claim here
demonstrates pointer control. Overall rung 4 status: **INSTRUMENTED**, not
request-reachable or exploit-proven.

Cheapest experiment to move it up a rung: build `6.0.5` `charon` with the
`eap-sim`/`eap-aka` plugins, configure a loopback-only IKEv2 responder that
terminates EAP-SIM locally, send a crafted EAP-SIM message with a zero-length
attribute, and capture the daemon ASan frames plus the exact wrapped
allocation — then repeat on `6.0.6` for the guard. Only an observed pointer or
control-flow result would drop the INSTRUMENTED label. Preserve the real-libc
negative result: if the daemon's copy also faults before writing chosen bytes,
that caps this path at rung 3 in practice, per the sibling nginx2root lesson.

All ground-truth items in the first section remain claims reproduced from
public sources; this brief proves the pinned code paths and their memory
effects in a synthetic frame, not advisory reachability, CVSS, or daemon
exploitability.

## Independent witness (closed 2026-11-21T08:12Z)

Witness request #669 is closed by verdict #675 (tape #675): ESTABLISHED AS
CLAIMED, no grade correction, rung 4 remains INSTRUMENTED, no replay owed and
no doc nit. The witness replayed unmodified `run.sh` from two clean
`git archive HEAD` (`6b9ac2d`) extractions plus the working tree: 54 PASS / 0
FAIL and raw trace
`sha256=57cd8943825f35a14f45ce134f3987c489aacbd080c6249a94c9dc808f1f3d6a`
byte-identical in all three. Its own primary-source fetches reproduced all
five pin hashes and its counterexample hunt found no benign-length false trip;
the real-libc rung-4 negative was confirmed independently. No brief revision
was required.
