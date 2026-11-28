# Freeradius2Shell status — live loopback replay and rung-4 control (2026-11-28)

Target: FreeRADIUS EAP-FAST SessionTicket (PAC-Opaque) stack overflow,
CVE-2026-127030 (CWE-787, CVSS 3.1 7.5, `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`).
Red Hat marks RHEL 10/9/8/7 affected; EAP-FAST is optional and not enabled by
default. Upstream vulnerable commit `3f802d74deef4c72e46f37fb9418d9787feaf748`;
fixed by `064567a08f3b9d9b4863fab6060fafe296ac7de9` (2026-10-14). No exact
fixed release tag is known from the sources read: the fix commit is the
boundary. Inherited harness evidence is in `reports/frontier-freeradius2shell.md`.

## Live result — rungs 1/2/3 in a real `radiusd` process

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
`freeradius-fixed/.../rlm_eap_fast.c:321` (line 322 assigns the errmsg).

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
  that plaintext. When the canary slot is left as marker bytes the live server
  still aborts before the return, but the chosen bytes were directly observed
  in the live `_session_ticket()` frame (see next section).

## Live stack layout and chosen-pointer execution (second wake)

Under `gdb -q -batch` (ASLR disabled by gdb), a breakpoint on
`__stack_chk_fail` stops the live vulnerable `radiusd` at
`rlm_eap_fast.c:383`. Read-only `bt`, `printf` and `x` commands (no register or
memory writes) measured the `_session_ticket()` frame at
`rbp = 0x7fffffffbba0`, destination `opaque_plaintext = 0x7fffffffbaf0`:

| slot | address | offset from destination |
|---|---|---|
| `opaque_plaintext` | `rbp-0xb0` | 0 (152 bytes) |
| stack canary | `rbp-0x18` | **152** |
| saved RBP | `rbp` | 176 |
| saved RIP | `rbp+8` | **184** |

The same offsets appeared in the earlier cut wake at a different stack base
(`rbp = 0x7fffffffbbd0`), so the relative layout is stable in this build;
absolute addresses depend on ASLR/environment. Full dumps:
`lab/freeradius2shell-live/r4l-gdb-key-known.log:891-908` and
`r4l-gdb-key-unknown.log:891-908`.

- **Key-unknown wire ticket** (`logs/ku/ticket.bin`, `sha256 f655d399…`):
  canary slot `0xbb2188cce836d0d9`, saved RIP `0x1bd2efa9ab0b6e3d` —
  ciphertext-derived, not choosable by the peer.
- **Key-known wire ticket** (`logs/kk/ticket.bin`, `sha256 94fd74f4…`):
  canary slot `0x4c45485332535549` (ASCII `IUS2SHEL`) and saved RIP
  `0x4c2d4c4c45485332` (ASCII `2SHELL-L`): chosen plaintext bytes from the
  wire at the measured saved-RIP offset, observed in the live process. That
  arm still aborts before the return, so no control flow transferred on it.

**Chosen-pointer execution (rung 4, live):** a third arm built the ticket so
plaintext bytes 152–159 carry the *same process's* stack canary and bytes
184–191 carry the address of a benign marker function. The canary and function
address were **read** from the gdb-stopped process at `main`
(`r4l-marker-gdb.log:5-6`: `R4L-CANARY fa3871fa3cb7f600`,
`R4L-MARKER 0x7ffff7fb9140`; no writes), put in the ticket, and sent from the
loopback peer. `r4l-marker-gdb.log:892-895` shows `PAC provided via ClientHello
SessionTicket extension`, `ERROR: PAC failed to decrypt`, then
`R4L-LIVE-BENIGN-MARKER` and
`[Inferior 1 (process 2444170) exited with code 052]` (octal 42). No
`__stack_chk_fail` line fired: the preserved canary let the function return
into the wire-supplied pointer. The committed marker ticket has
`sha256 a26dd3a5…` on both builds; that digest is run-specific because it
embeds the per-process canary. A fresh `r4l-marker-run.sh` reads a new canary
and produces a different ticket; `r4l-fixed-run.sh` reproduces this digest
only through its recorded `R4L_CANARY` default.

Controls: **safe input** (`hdr.length=100`, `dlen=52`,
`logs/r4l-safe/ticket.bin` `sha256 4ecbf2a5…`) got Access-Reject with `PAC
failed to decrypt` and no canary abort; **fixed commit** `064567a08f3b`
rejected the identical marker ticket with `ERROR: PAC is too long, sending
alert to client` (`r4l-fixed-marker-radiusd.log:873-874`) and sent
Access-Reject.

Conditions for this control-flow demonstration (all lab-only): the exact
vulnerable commit, EAP-FAST enabled, a loopback client with the lab shared
secret, the configured 32-byte `pac_opaque_key` to choose plaintext, a
per-process canary read via gdb (a remote peer cannot derive it), ASLR off,
and a benign function preloaded via `LD_PRELOAD` (`r4l-marker.c` /
`r4l-marker.so`) whose address was read at `main`. The pointer target is
therefore **not** wire-only: this is rung 4, not rung 5.

New digests (`lab/freeradius2shell-live/`):

| artifact | SHA-256 |
|---|---|
| `peer-marker.py` | `1addb493051956fad759ca951c836dfcca6436989afb60027e4afab46dd041fd` |
| `peer-safe.py` | `2dbee16736a6db848d6bfd5b362998c4b359f75b375e9908b3bc503d94e99945` |
| `r4l-marker.c` | `f3385e57aa652038e1c072db980ce3a9ec8c7288ad47587511e5e12c79c55c62` |
| `r4l-marker.so` | `a015f223d9dc4753ea7906dcf015f17afba77fa3ef7a3767d14f76bc6743f4b0` |
| `r4l-gdb.cmd` | `c5cc738125588537a8ef985b11690b64e011a54ce178053af4a9b9061dc95951` |
| `r4l-marker.cmd` | `00e46b7c0cff6b91107c4983fdac0d55151f658c22bb47881d8fcd07e9004b67` |
| `logs/r4l-marker/ticket.bin` = `logs/r4l-fixed-marker/ticket.bin` | `a26dd3a58e480bd566dfc6f2f5fe0f303a1beddc66a9c11150f95ffd28ad4aaa` |
| `logs/r4l-safe/ticket.bin` | `4ecbf2a58b682d54228735e3501d471c92bb2f8d3e251bbb353a2b744b7b2f28` |
| `r4l-gdb-key-known.log` | `7376d0577f608fa8c4012d12084b26dd9fc1ecc82fa90e61fbdd6a286be75491` |
| `r4l-gdb-key-unknown.log` | `e0b9f4065deeceaf6743b2c889827bb11f239223bbb9a31567b96189c101f39e` |
| `r4l-marker-gdb.log` | `b1fdb191e9e40b81b20f08aaeb0a296d09cb32f9d17f8be7fbb7b9396911fd4a` |
| `r4l-fixed-marker-radiusd.log` | `2e74bed1e46a54fc79477af13045c2d8006a001cfbf2abc21cbc818076d00e14` |

The marker-ticket row above is pinned to the recorded canary; a fresh replay
should not expect that digest to match.

## Honest rung ladder after this wake

- **Rung 1 (trigger): PASS, live.** Crafted 260-byte ticket drives a real
  `radiusd` into `_session_ticket()`; the fixed build rejects the same bytes.
- **Rung 2 (state failure): PASS, live.** `*** stack smashing detected ***`
  on key-known and key-unknown tickets; the canary-preserving arm instead
  reaches its chosen marker.
- **Rung 3 (memory corruption): PASS, live.** Canary plus the exact
  `dlen=208` / 152-byte source binding; the debugger dump shows chosen bytes
  at destination offsets 152 (canary) and 184 (saved RIP). ASan remains blind
  (write inside un-instrumented libcrypto) — inherited negative.
- **Rung 4 (impact): PASS, live, with stated lab-only conditions.** A wire
  ticket carrying the process's canary and a chosen benign function address
  made the real `radiusd` print `R4L-LIVE-BENIGN-MARKER` and exit 42. The
  standalone harness's 200-byte-offset marker (rc 42) remains a separate,
  simpler demonstration.
- **Rung 5: not attempted and not claimed.** No shell command and no
  wire-only pointer derivation: the marker address came from a debugger
  symbol read and an `LD_PRELOAD` library, the canary from a debugger read.

Conditions for the live rung-4 result: exact vulnerable commit, EAP-FAST
explicitly enabled, loopback client with the lab shared secret, configured
`authority_identity`/A-ID and 32-byte `pac_opaque_key`, gdb read of the
per-process canary and marker address (no writes), ASLR off and an
`LD_PRELOAD` benign function. No off-loopback probe, no scan, no external
target, no process memory or register written by the debugger.

## Independent witness replays

Witness W384 (03:28–03:36Z, `.mishe-tauftauf/artifacts/witness-w384/detail.md`)
replayed the live rungs 1/2/3 claim: 7/7 live digests recomputed equal, both
worktree HEADs confirmed, canary abort on key-known and key-unknown tickets,
fixed build rejects with `PAC is too long`. Its read-only GDB replay observed
chosen key-known bytes at `dst+144..169`, canary slot `dst+152` and saved-RIP
slot `dst+184` (`0x4c2d4c4c45485332`) in the live stack.
Witness W385 (03:50–03:53Z, `.mishe-tauftauf/artifacts/witness-w385/detail.md`)
replayed the rung-4 claim: all 13 report-table digests recomputed equal, the
unmodified `r4l-marker-run.sh` produced the marker/exit-42 window, the fixed
and safe arms stayed clean, and a separate read-only GDB probe broke at
`benign_marker` with `$rip` and the return slot holding the wire-supplied
address. Both verdicts: **ESTABLISHED AS LABELED**, grade-neutral, NO r5.
The W384 "no chosen value observed" NIT and W385's digest-specificity and
fix-guard line-citation NITs are folded above; rung 4 stays live but lab-only.

## Reproduce

```
cd lab/frontier/freeradius2shell && bash run.sh          # harness differential
cd lab/freeradius2shell-live/freeradius-src
# configure/make/install as above; git worktree add ../freeradius-fixed 064567a08f3b
cd ..

# live crash (vulnerable, port 18120):
LD_LIBRARY_PATH=$PWD/talloc-prefix/usr/lib/x86_64-linux-gnu \
  ./install/sbin/radiusd -X -d ./install/etc/raddb -i 127.0.0.1 -p 18120
python3 peer.py key-unknown --outdir logs/ku
python3 peer.py key-known   --outdir logs/kk

# measured offsets + chosen bytes at saved RIP (gdb, read-only):
bash r4l-run.sh key-known && bash r4l-run.sh key-unknown

# chosen-pointer execution: canary/marker read from the same process, then wire
bash r4l-marker-run.sh

# safe input (dlen=52) and fixed-commit differential (port 18122):
./install/sbin/radiusd -X -d ./install/etc/raddb -i 127.0.0.1 -p 18120 &
python3 peer-safe.py key-unknown --outdir logs/r4l-safe
LD_LIBRARY_PATH=$PWD/talloc-prefix/usr/lib/x86_64-linux-gnu \
  ./install-fixed/sbin/radiusd -X -d ./install-fixed/etc/raddb -i 127.0.0.1 -p 18122 &
python3 peer.py key-unknown --port 18122 --outdir logs/fixed
bash r4l-fixed-run.sh   # same marker ticket against the fixed build
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
- A gdb command file edit accidentally deleted its `run` line, so two
  key-unknown attempts started no server (`STEP1: no reply`) and produced no
  breakpoint output; the line was restored and both arms re-run.
- The first tail-dump expression `&opaque_plaintext+144` resolved to an
  unreadable address in gdb; `$rbp-0xb0+144` gave the intended byte range.
- A key-known ticket whose canary slot is left as marker bytes aborts before
  the return; only the canary-preserving arm reaches the chosen pointer.

## What would change this assessment

- A wire-only derivation of the per-process canary (or a target whose address
  is wire-derivable without a debugger read) would make the rung-4 pointer
  control attacker-reachable under the stated framing.
- A benign command side effect produced solely by wire input, with
  vulnerable/fixed/safe-input controls and independent replay, would be
  required before any rung 5 claim.
- A live replay where EAP-FAST is disabled, or where the A-ID gate rejects,
  would narrow the network framing claim while leaving the harness result
  intact.
