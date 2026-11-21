# strongswan2shell — status

Admitted 2026-11-21 ~08:1xZ by the operator under standing approval #6 on
frontier's commits `37e0b1a` / `cda059a` / `6b9ac2d` and brief
[frontier-strongswan2shell.md](frontier-strongswan2shell.md). Claim source:
upstream advisory
<https://www.strongswan.org/security/CVE-2026-35330.html>, published
2026-04-22. It reports an infinite loop or a heap-based buffer overflow in
`libsimaka` processing certain EAP-SIM/AKA attributes, "potentially" leading
to remote code execution. All versions since 4.3.6 are affected; fixed in
6.0.6. CVSS is not stated by the advisory (UNKNOWN). The advisory says RCE
"might be possible" and does not claim demonstrated control flow; public
exploit-module claims (Exploit-DB 52587) are unverified here. Fix commit
`aa5aaebc33e0f326d8a0dbe01b236f2bfa0e6ea1` adds `hdr->length == 0 ||` to
the guards at `src/libsimaka/simaka_message.c:419` and `:442`.

Claimed trigger: in a zero-length EAP-SIM/AKA attribute header, the length
byte 0 makes `hdr->length * 4 - 2` (default) or `- 4` (`AT_RAND`) underflow
`size_t`; `chunk_skip()` is a no-op and the wrapped length reaches both
`malloc()` and `memcpy()` in `add_attribute()` (`:257-260`). The wrapped
allocation is 12/14 bytes against a 16-byte `attr_t` on this host, so even
the `attr->len` store at `:258` is out of bounds; the copy source is
attacker-supplied attribute bytes. `AT_PADDING`/`AT_ENCR_DATA` take the
no-sink, no-progress path (the advisory's infinite loop). EAP-SIM/AKA must
terminate on the VPN server; RADIUS offload is explicitly not vulnerable.
Pins, hashes, raw URLs and preserved failed attempts:
`lab/frontier/strongswan2shell/PROVENANCE.md`.

- Harness: `bash lab/frontier/strongswan2shell/run.sh` — 54 PASS / 0 FAIL,
  raw trace `sha256=57cd8943825f35a14f45ce134f3987c489aacbd080c6249a94c9dc808f1f3d6a`.
- Operator replay ~08:1xZ from two clean `git archive HEAD` (`97d53ed`)
  extractions into separate absolute directories: 54 PASS / 0 FAIL in both,
  raw trace
  `sha256=57cd8943825f35a14f45ce134f3987c489aacbd080c6249a94c9dc808f1f3d6a`
  — byte-identical between directories, to the working-tree replay and to the
  brief.
- Rungs 1/2/3 on verbatim pinned blocks from `6.0.5` (affected) and `6.0.6`
  (fixed): type `AT_IDENTITY` (14) with length byte 0 requests a
  `18446744073709551614`-byte copy at `:260` and leaves the input unchanged;
  `AT_RAND` (1) requests `18446744073709551612`; `AT_ENCR_DATA` (130) reaches
  the underflow but calls no sink. The allocation wraps to 14 bytes (default)
  and 12 bytes (RAND), and the vulnerable build accepts the attribute
  (`reject=0`, `add_calls=1`); the fixed guards call `invalid_length()`
  (`type=14` / `type=1`, no `memcpy`) while still adding a benign attribute.
  ASan reports `heap-buffer-overflow`, `WRITE of size 8` at pinned
  `simaka_message.c:258 in add_attribute` inside 14-byte and 12-byte regions;
  benign and fixed ASan runs are clean.
- Rung 4 INSTRUMENTED only, with two preserved outcomes. Under a bounded-copy
  collaborator (131072 bytes, still logging the wrapped requested length),
  chosen `0x5a` bytes are observed at offsets 16, 32, 64, 4096 and 65536 past
  `attr->data` on both vulnerable paths (`match=1`). Under the real host libc
  with the genuine wrapped length, the copy faults at `src_base - 0x20`
  before writing: those offsets stay `0x00` (`match=0`). No pointer, saved
  return address, heap metadata, function pointer, control-flow diversion or
  marker execution was observed or attempted; the guard mapping and bounded
  copy are instrumentation.
- UNKNOWN: live daemon, IKEv2/EAP reachability, whether EAP-SIM/AKA terminates
  locally in any stock config, shipping allocator and compile flags, real
  daemon ASan frames, exploit-module claims, and any post-write pointer
  control. All external claims remain claims. No probe was sent off loopback.
  Witness verdict #675 (08:11Z): ESTABLISHED AS CLAIMED, no grade correction,
  rung 4 INSTRUMENTED only.

Cheapest next rung: build `6.0.5` `charon` with the `eap-sim`/`eap-aka`
plugins, configure a loopback-only IKEv2 responder terminating EAP-SIM
locally, send a crafted EAP-SIM message with a zero-length attribute, capture
the daemon ASan frames and the exact wrapped allocation, then repeat on
`6.0.6` for the guard. Only an observed pointer or control-flow result would
drop the INSTRUMENTED label. If the daemon's copy faults before writing chosen
bytes, preserve that as a negative result — the sibling nginx2root lesson
applies.
