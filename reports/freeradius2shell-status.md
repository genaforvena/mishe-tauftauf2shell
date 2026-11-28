# Freeradius2Shell status — live loopback replay (2026-11-28)

Target: FreeRADIUS EAP-FAST SessionTicket (PAC-Opaque) stack overflow,
CVE-2026-127030 (CWE-787, CVSS 3.1 7.5, `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`).
Red Hat marks RHEL 10/9/8/7 affected; EAP-FAST is optional and not enabled by
default. Upstream vulnerable commit `3f802d74deef4c72e46f37fb9418d9787feaf748`;
fixed by `064567a08f3b9d9b4863fab6060fafe296ac7de9` (2026-10-14). No exact
fixed release tag is known from the sources read: the fix commit is the
boundary. Inherited harness evidence is in `reports/frontier-freeradius2shell.md`.

## Live result — rungs 1/2/3 PASS in a real `radiusd` process

Built the vulnerable source tree verbatim at the parent commit with EAP-FAST
enabled and ran a synthetic RADIUS/UDP peer against a **loopback-only**
listener. The oversized ClientHello SessionTicket reaches
`_session_ticket()` in the live server and the process aborts under the
compiler's stack canary. Same bytes against the exact upstream fix commit
are rejected before the decrypt, with no crash.

Build/config (all under `lab/freeradius2shell-live/`, no off-host traffic):

- `git rev-parse HEAD` = `3f802d74deef4c72e46f37fb9418d9787feaf748`.
  `libtalloc-dev`/`libtalloc2` provisioned by `apt-get download` +
  `dpkg-deb -x` into `talloc-prefix/` (no root). `configure --prefix=.../install
  --with-talloc-lib-dir=... --with-talloc-include-dir=...`, `make -j6`,
  `make install` all rc 0; `rlm_eap_fast` built and linked.
- `authority_identity = "freeradius2shell-lab"`,
  `pac_opaque_key = "0123456789abcdef0123456789ABCDEF"` (exactly 32 bytes),
  `default_eap_type = fast`, `fast { virtual_server = inner-tunnel }`,
  installed demo certs. `radiusd -XC`: "Configuration appears to be OK".
- `radiusd -X -d install/etc/raddb -i 127.0.0.1 -p 18120` (auth listener
  bound to 127.0.0.1:18120 only; acct on 18121).
- `python3 peer.py <mode> --outdir logs/<mode>` performs two RADIUS
  Access-Requests with valid HMAC-MD5 Message-Authenticator: Response/Identity
  (`bob`) → Access-Challenge with State and the server's EAP-FAST A-ID TLV →
  Response/FAST (type 43, flags 0x00) carrying a TLS 1.2 ClientHello with a
  SessionTicket extension (type 35). Extension payload is the raw 260-byte
  PAC-Opaque: `hdr.type=2`, `hdr.length=256`, `aad = MD5(authority_identity)`
  (`9c16921152e77c27c0179af99c03e810`), 16-byte IV, 16-byte tag, 208 bytes
  ciphertext. Gates at `rlm_eap_fast.c:273,296,301,306` pass; `dlen = 256-48
  = 208` reaches `EVP_DecryptUpdate()` with a 152-byte stack destination.

Observed in `lab/freeradius2shell-live/radiusd-live.log` lines 1094–1097
(key-unknown replay):

```
(5) eap_fast: (TLS) FAST - recv TLS 1.3 Handshake, ClientHello
(5) eap_fast: PAC provided via ClientHello SessionTicket extension
(5) eap_fast: ERROR: PAC failed to decrypt, sending alert to client
*** stack smashing detected ***: terminated
```

The peer received no reply (6 s timeout). Independent replay with the
key-known ticket gave the same abort at `radiusd-keyknown.log:884-887`.

Fixed differential: worktree at `064567a08f3b`, same configure/make/install
into `install-fixed/`, same config copied over. The identical ticket
(`sha256 f655d399…` on both sides) produced
`radiusd-fixed.log:872-874`:

```
(1) eap_fast: (TLS) FAST - recv TLS 1.3 Handshake, ClientHello
(1) eap_fast: PAC provided via ClientHello SessionTicket extension
(1) eap_fast: ERROR: PAC is too long, sending alert to client
```

The fixed server stayed up and sent Access-Reject; no canary abort. The guard
is `if ((size_t)length > sizeof(*opaque) - sizeof(opaque->hdr))` (cap 148),
`freeradius-fixed/.../rlm_eap_fast.c:322`.

Pinned digests (`lab/freeradius2shell-live/logs/live-digests.txt`):

| artifact | SHA-256 |
|---|---|
| `peer.py` | `69ff02729274de1752d08644c1efe3f4d4f693920822430a7f836e6578890fe4` |
| `logs/ku/ticket.bin` = `logs/fixed/ticket.bin` | `f655d3998545f840d57d09963941cec6bd6b4da26db2238bc12369a18e702103` |
| `logs/kk/ticket.bin` | `94fd74f4a6130e435cc9defab32fb295950738f9a5ee0b5883d2fc2f5f8bc8d8` |
| vulnerable `install/sbin/radiusd` | `abce05d29706783a8997b464c6fa3cd7004f62cdbe99a6fa7f00e963f6db3491` |
| fixed `install-fixed/sbin/radiusd` | `ca397146fdbed20b0433aeb4937067da15900ab7f033fe2db34e07c408e38925` |
| installed `mods-available/eap` | `4fbb8bfb56c8e02f558b334dde28ab234901f2015d70dfb4e6e89be1d8a2e4a6` |

## Byte control: key-known vs key-unknown

- **Key-unknown (remote peer)**: the server's EAP-FAST Start challenge carries
  its 16-byte A-ID (`mod_session_init`, `rlm_eap_fast.c:625`), so a peer can
  satisfy the `aad` gate without the PAC key. The peer controls `hdr.length`
  and the ciphertext bytes, but GCM plaintext = ciphertext XOR a keystream
  derived from the secret `pac_opaque_key`; written stack bytes are not
  choosable. This supports the vendor's availability-only framing, now
  observed in a live process.
- **Key-known (lab)**: `peer.py key-known` encrypts a chosen 208-byte plaintext
  (`FREERADIUS2SHELL-LIVE-MARKER-…`) with the configured AES-256-GCM key and
  IV; offline check confirms the emitted ciphertext decrypts byte-exactly to
  that plaintext. The live server still aborts before tag verification.
  No chosen value has been observed in the live process's stack, so this does
  not establish live control-flow hijack.

## Honest rung ladder after this wake

- **Rung 1 (trigger): PASS, live.** Crafted 260-byte ticket drives a real
  `radiusd` into `_session_ticket()`; fixed build rejects the same bytes.
- **Rung 2 (state failure): PASS, live.** `*** stack smashing detected ***`
  from the real process on both key-known and key-unknown tickets.
- **Rung 3 (memory corruption): PASS, live.** Canary plus the exact
  `dlen=208` / 152-byte source binding. ASan remains blind (write inside
  un-instrumented libcrypto) — inherited negative, not re-asserted here.
- **Rung 4 (impact): PASS in the standalone harness only.** Chosen marker at
  the measured 200-byte saved-RIP offset executes there (rc 42); no chosen
  value observed in the live process and the live stack layout is unmeasured.
- **Rung 5: not attempted**, no benign-command side effect from wire input.

Conditions for the live result: EAP-FAST explicitly enabled, a known
`authority_identity`/A-ID, a loopback client with the lab shared secret, and
the exact vulnerable commit. No off-loopback probe, no scan, no external
target.

## Reproduce

```
cd lab/frontier/freeradius2shell && bash run.sh          # harness differential
cd lab/freeradius2shell-live/freeradius-src
# configure/make/install as above; git worktree add ../freeradius-fixed 064567a08f3b
LD_LIBRARY_PATH=$PWD/../talloc-prefix/usr/lib/x86_64-linux-gnu \
  ../install/sbin/radiusd -X -d ../install/etc/raddb -i 127.0.0.1 -p 18120
cd .. && python3 peer.py key-unknown --outdir logs/ku
python3 peer.py key-known --outdir logs/kk
# fixed build on 127.0.0.1:18122 with install-fixed/etc/raddb:
python3 peer.py key-unknown --port 18122 --outdir logs/fixed
```

## Negative results preserved

- First peer used plain MD5 for Message-Authenticator; server rejected it
  ("invalid Message-Authenticator"). FreeRADIUS uses HMAC-MD5
  (`src/lib/radius.c:3133`); fixed in `peer.py`.
- Initial EAP header length was `5 + rec` instead of `6 + rec`; server
  rejected a "Malformed EAP packet"; corrected.
- First fixed-config startup loaded modules from the vulnerable prefix
  (`rlm_radutmp` magic mismatch); fixed by setting `prefix = .../install-fixed`
  in `install-fixed/etc/raddb/radiusd.conf`.
- Plaintext verification initially failed with `InvalidTag` because the
  ticket deliberately zeroes the GCM tag (the write precedes verification);
  verified instead by comparing emitted ciphertext with the encryption of
  the chosen plaintext.

## What would change this assessment

- A chosen value observed at a known offset in the **live** process (debugger
  or benign marker) would promote rung 4 from harness-only to live.
- A wire-only benign command side effect with vulnerable/fixed/safe-input
  controls would be required before any rung 5 claim.
- A live replay where EAP-FAST is disabled, or where the A-ID gate rejects,
  would narrow the network framing claim while leaving the harness result
  intact.
