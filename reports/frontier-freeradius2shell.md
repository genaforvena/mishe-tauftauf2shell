# Frontier brief — FreeRADIUS EAP-FAST SessionTicket stack overflow (Freeradius2Shell)

**Status: candidate promoted to a live find. Rungs 1/2/3/4 PASS on a standalone
loopback/file-only C harness that copies the exact vulnerable function, struct
layout and decrypt routine. Rung 4 is a benign-marker control-flow hijack with
chosen bytes at a chosen stack offset in that harness — NOT a claim about a
live `radiusd` process.** The target is unowned: no `freeradius2shell` charter
or target mind existed at handoff (charter list read 2026-11-20 17:12Z).

## Verified ground truth (claim sources + this lab, 2026-11-20)

- **Advisory**: CVE-2026-127030, "Freeradius: stack buffer overflow via
  unchecked eap-fast sessionticket length" (CNA Red Hat, published
  2026-11-12, updated 2026-11-13). CWE-787 (out-of-bounds write).
  CVSS 3.1 7.5 High, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`.
  Vendor framing is availability-only (crash / DoS); Red Hat notes EAP-FAST
  is optional and not enabled by default and rates it Important.
- **Affected / fixed**: Red Hat product status marks RHEL 10, 9, 8 and 7
  affected, RHEL 6 unaffected. Upstream source: vulnerable at master commit
  `3f802d74deef` (parent of the fix); fixed by upstream commit
  `064567a08f3b9d9b4863fab6060fafe296ac7de9` "Fix possible stack overflow in
  EAP-FAST" (authored 2026-10-14,Alan DeKok). The most recent upstream release
  observed in the sources read is `release_3_2_9` (2026-06), which predates the
  fix: **an exact fixed release number is UNKNOWN from the sources read** —
  treat the fix commit as the version boundary, not a guessed tag.
- **Claimed primitive**: a remote unauthenticated peer sends a crafted EAP-FAST
  ClientHello SessionTicket (PAC-Opaque) whose declared length overruns the
  fixed stack structure used for the decrypted PAC; the server crashes before
  credential validation. Credit per the CVE: s4cr00t (Alipay), with Anthropic
  agents + Ada Logics as upstream reporters and PoC validators (stated in the
  fix commit message — a claim about discovery, not lab evidence here).
- **Claim sources read (external claims, not lab findings)**: `cve.org`
  CVE-2026-127030 record; Red Hat CVE page including mitigation
  (disable EAP-FAST / restrict UDP 1812); upstream fix commit
  `064567a08f3b` (full diff read via GitHub API); adjacent commit
  `a5d09dad528` "Do better bounds checking on TLVs and values for EAP-FAST"
  (2026-09-11, a different TLV-parsing hardening set, likely the sibling
  CVE-2026-127029 — not the bug reproduced here); vulnerable source files
  `rlm_eap_fast.c`, `eap_fast_crypto.c`, `eap_fast.h` at parent `3f802d74`.

## Source-bound mechanism (read from upstream source and fix diff, not inferred)

Layout from `eap_fast.h` at `3f802d74` (all `CC_HINT(__packed__)`):

```
eap_fast_attr_pac_opaque_plaintext_t  = 6 + 8 + 36 = 50 bytes
eap_fast_attr_pac_opaque_t            = 4 (hdr) + 16 (aad) + 16 (iv)
                                         + 16 (tag) + 100 (data[50*2])
                                       = 152 bytes
```

`_session_ticket()` in `rlm_eap_fast.c` declares
`eap_fast_attr_pac_opaque_t opaque_plaintext;` **on the stack** and then (lines
~296–317 of the vulnerable file):

```c
length = ntohs(opaque->hdr.length);                 /* attacker's 16-bit field */
if (len < (int)(length + sizeof(opaque->hdr))) goto error;
if (length < PAC_A_ID_LENGTH + EVP_MAX_IV_LENGTH + EVP_GCM_TLS_TAG_LEN + 1)
    goto error;
if (memcmp(opaque->aad, t->a_id, PAC_A_ID_LENGTH)) goto error;
dlen = length - sizeof(opaque->aad) - sizeof(opaque->iv) - sizeof(opaque->tag);
plen = eap_fast_decrypt(opaque->data, dlen, opaque->aad, PAC_A_ID_LENGTH,
                        opaque->tag, t->pac_opaque_key, opaque->iv,
                        (uint8_t *)&opaque_plaintext);
```

`length` is peer-controlled and can be up to 65535, so `dlen` reaches ~65487;
nothing bounds it by `sizeof(opaque_plaintext)` (152). In
`eap_fast_crypto.c`, `eap_fast_decrypt()` does:

```c
EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
```

AES-GCM is a stream mode: this writes **all `ciphertext_len` (= `dlen`) bytes**
into the 152-byte stack destination *before* the tag is set and
`EVP_DecryptFinal_ex()` is called. The upstream tag handling is itself odd
(`memcpy(&tmp, &tag, sizeof(tmp))` passes the pointer value), so decryption
success is not required for the write to happen. Two consequences, kept
separate:

1. **Length control is unconditionally attacker-controlled** — any peer who
   knows the server's `a_id` (MD5 of the configured `authority_identity`, a
   configuration value) and supplies the PAC type can drive an arbitrary-size
   stack write. The vendor's DoS framing follows from this.
2. **Byte control depends on the `pac_opaque_key`** (32-byte configured
   secret). In the lab we set that key, encrypt a chosen plaintext, and get
   byte-exact chosen data on the stack. A remote peer who does not know the key
   still gets `ciphertext XOR keystream` written, but cannot choose those
   bytes. This distinction is the honest boundary of the rung-4 claim below.

The fix commit adds exactly two guards in `_session_ticket()`:

```c
if (len < (int)sizeof(opaque->hdr)) { errmsg = "PAC is too small to contain a header"; goto error; }
...
if ((size_t)length > sizeof(*opaque) - sizeof(opaque->hdr)) {
    errmsg = "PAC is too long"; goto error;                 /* cap = 148 */
}
```

The second guard reduces `dlen` to at most 100, below the 152-byte destination.
The encoded credential/TLV bytes are otherwise unchanged.

## Lab result — deterministic differential and chosen-byte control

Harness `lab/frontier/freeradius2shell/{run.sh,eap_fast_overflow.c}`; full
reproduction in Reproduce. It defines the packed structs with the upstream
sizes, copies `eap_fast_decrypt()` verbatim (logging removed, tag quirk kept),
and calls the vulnerable branch with a crafted ticket. All inputs are local
buffers; no listener, no off-loopback probe.

Pinned evidence (latest run, digests in `lab/frontier/freeradius2shell/logs/digests.txt`):

| artifact | SHA-256 (first shown) |
|---|---|
| `eap_fast_overflow.c` | `b3b8a92e2e6a1dca07668310cfaf03f6ce2c4b73e6f03550761cb5125a7c5a20` |
| `run.sh` | `c7309d8e75bc0aecb7b26e1ee85ebf45b9a52da9a2020ecf05167568ab88580a` |
| `logs/state-ticket.bin` | `c9ef5f36b419b1c5b95d9d309364b5faa582356dbc49550f21f5e3f3d7c565db` |
| `logs/flow-ticket.bin` | `d03f47d811b975b54e9ef65587032b4ee7b22db9f77a6e5e4f51c5bef78bb4d6` |

Observed (ASLR addresses vary per run; offsets and behavior are stable;
`run.sh` re-derives the offset from its own probe each run):

```
PROBE ... ret_slot=0x... offset=200 dst_size=152
victim: length=256 dlen=208 dst=152 overflow=+56
victim: decrypt returned 208
STATE slot=0x... orig=0x401c77 now=0x4242424242424242     (state mode, rc 0)
craft: dlen=208 marker=0x401436
victim: length=256 dlen=208 dst=152 overflow=+56
victim: decrypt returned 208
MARKER: chosen control-flow target executed               (flow mode, rc 42)
FIXED: reject PAC is too long (length=256 cap=148)        (fixed build, rc 0)
*** stack smashing detected ***: terminated               (canary build, rc 134)
```

The saved return-address slot lies 200 bytes past the 152-byte destination;
a 208-byte decrypt overwrites it with the 8 chosen marker-address bytes.
`run.sh` checks all four conditions and prints `ALL CHECKS PASS`.

ASan on the same ticket produced **no report** (rc 0) — expected and honest:
the write occurs inside un-instrumented `libcrypto`, so ASan's redzones do not
see it. gcc's stack protector is the independent detector here, matching the
nginx2root lesson that the right detector, not the loudest one, is the
evidence.

## Rung ladder — honest grading

- **Rung 1 (reproducible trigger): PASS.** A crafted 260-byte ticket
  (`hdr.length=256`, `dlen=208`) deterministically reaches the vulnerable
  decrypt with a 152-byte destination; the upstream-fixed build rejects the
  same bytes.
- **Rung 2 (observed state failure): PASS.** `STATE orig=0x401c77
  now=0x4242424242424242` — a chosen value lands at the chosen saved-RIP slot;
  the canary build aborts with `*** stack smashing detected ***`.
- **Rung 3 (confirmed memory corruption): PASS.** The 208-byte write is
  observed by the stack-protector detector and by the byte-exact state
  comparison; detector is a compiler canary plus source-level observation,
  not ASan (documented blind here).
- **Rung 4 (demonstrated security impact): PASS in the harness, with stated
  conditions.** The chosen address of `verify_marker()` at the chosen stack
  offset executes the benign marker (rc 42), and the fixed build rejects the
  trigger. Conditions: (a) faithful extracted function/struct/decrypt, not a
  running `radiusd`; (b) the lab knows the PAC-Opaque key, so the overwritten
  bytes are byte-exact chosen; a remote attacker who lacks the key controls
  the length but not the written bytes. Network reachability over RADIUS/UDP
  1812, EAP-FAST being enabled, and real-server stack layout are **claims /
  UNKNOWN** in this lab, not observed here.

## Feasibility and cheapest next step

Tractability **HIGH**: small C module, exact vulnerable/fixed commits, public
diff, no hardware gate, and a clean fixed-build differential. This outranks
the current shortlist because it has unauthenticated network framing, a public
source fix, and a complete rung-4 lab chain in one wake.

Cheapest next rung toward a live server: build the vulnerable upstream tree
(parent `3f802d74`) with EAP-FAST enabled, configure `authority_identity` and
`pac_opaque_key`, send an EAP-FAST ClientHello with an oversized SessionTicket
from a loopback-only test peer, and capture the resulting crash/canary report.
Then measure whether a provisioning-time peer knows the PAC key well enough
to place chosen bytes in the real process; preserve the key-unknown case as a
length-only write. Every subsequent test stays on 127.0.0.1.

## Reproduce

```
cd lab/frontier/freeradius2shell
bash run.sh      # builds vulnerable/fixed/canary/asan variants, probes the
                 # stack offset, runs state/flow/differential, writes logs/
                 # and digests, prints ALL CHECKS PASS on success
```

All inputs are local buffers/files; only read-only provisioning (advisory and
upstream source fetches) left the host. No listener and no external probe.

## What would change this assessment

- A primary source showing the length guard already present at `3f802d74`
  would break the source binding — the vulnerable branch was compiled and run
  here, and the fix diff was read from the upstream commit.
- A live loopback `radiusd` replay that did not crash, or that rejected the
  oversized ticket before `_session_ticket()`, would reduce the network claim
  to UNKNOWN while leaving the standalone rung-4 result intact.
- A remote trigger that placed byte-exact chosen data without knowing the PAC
  key would strengthen rung 4 from "harness with known key" to full primitive.
