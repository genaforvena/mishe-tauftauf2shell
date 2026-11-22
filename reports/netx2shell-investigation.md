# netx2shell — CVE-2026-93475 investigation (wake W1, 2026-11-22)

Status: **rung 4 (chosen bytes at a chosen offset) MEASURED on the pinned
vulnerable build by direct call and by TLS-protocol-arrived certificate.**
Host TCP loopback is a structural negative in this tree (no NetX host driver).
Independent witness replay #1262 returned ESTABLISHED at the claimed scope.
No rung 5. Build and input pins are in `lab/frontier/netx2shell/PROVENANCE.md`;
the starting rung-3 evidence is in `reports/frontier-netx.md`.

## What changed this wake

Frontier left two explicit UNKNOWNs: whether the ASan report's redzone write
corresponds to attacker-chosen bytes at a chosen `.bss` offset, and whether a
network-arrived Certificate message reaches the fault. This wake closed the
first one with a plain (non-ASan) build of the **unmodified** pinned verifier;
the second is still open.

### Plain-build readback, real upstream fixture

`harness/build-plain.sh` compiles the same source list as the committed ASan
harness with `-g -O0 -fno-omit-frame-pointer -no-pie` and no sanitizer, for
both pins. The `decrypted_signature[512]` static at
`nx_secure_x509_certificate_verify.c:28` resolves as a gdb debug symbol; no
library or harness source was patched for the readback.

With the real upstream 8192-bit DER fixture, the plain vulnerable build writes
**exactly 1024 bytes** at `decrypted_signature+0 .. +1023` (1017 non-zero),
leaving byte 1024 and beyond at their pre-verification value (zero). The ASan
redzone boundary at +512 is therefore a real 512-byte overwrite of adjacent
`.bss`, not a sanitizer artifact: the neighbouring `decrypted_signature[512]`
of `nx_secure_x509_crl_verify.c` begins at +576 and is inside the overwritten
range. Evidence: `harness/evidence-w1/vuln-fixture-bss-before-after.txt`.

### Chosen-byte control

All three operands of the RSA operation are attacker-supplied in the advisory's
pre-auth model (peer certificate's modulus and exponent, child certificate's
signature). The plain harness's existing `manual` mode already lets them be
set directly, and gdb's `restore` writes the three byte arrays into the
harness's own buffers after `main`'s memset — again with no source patch.

Construction: choose a 512-byte signature `s = 0x40 || ff*511`, exponent
`e = 2`, and a fully chosen 1024-byte output `T`; set the modulus to
`n = s² − T`. Then `s² mod n == T` exactly, so the vulnerable
`_nx_crypto_huge_number_extract` writes the chosen `T` into the destination.

- Run A: `T[512:520] = de ad be ef ca fe ba be`. Observed 1024 output bytes
  match `T` byte for byte (`A exact`).
- Run B changes only the chosen byte at offset 512 to `5a`. Observed output
  differs from A in **exactly one byte**: offset +512, `de` → `5a`; offset +511
  and +513 and every other byte are unchanged (`B exact`, one diff).
- Offset +512 is the first byte past the declared 512-byte
  `decrypted_signature` array; this is chosen-byte-at-chosen-offset on the
  plain build, not a redzone read.
- The same crafted inputs on the pinned **fixed** build produce an all-zero
  buffer and `verify_status=131074`: its RSA-init modulus-length guard rejects
  the 8192-bit key before the operation. The real fixture still rejects at
  parse on that build (`parse_status=418`), so both fix hunks are exercised.
- The same crafted inputs on the existing ASan vulnerable build fault in the
  same frame as frontier's fixture run
  (`_nx_crypto_huge_number_extract` at `nx_crypto_huge_number.c:1783`,
  `WRITE of size 1` 0 bytes after `decrypted_signature`).
- A 1-byte exponent `e = 1` control writes only 512 bytes and produces no
  overflow: negative control, kept as evidence that the chosen-byte result is
  not an artifact of the harness.

Raw logs and the deterministic generator/runner:
`lab/frontier/netx2shell/harness/evidence-w1/` (`gen-crafted.py`, `run.sh`,
`mod.bin`/`sig.bin`/`exp.bin` for A and `b/`, and the five gdb/ASan logs).
`bash harness/evidence-w1/run.sh` regenerates all of them in ~4 s.

## Honest boundary

- The chosen-byte control is a **direct call** into the real pinned verifier:
  `manual` mode sets the issuer's key fields directly and does not parse a DER
  certificate. The separate TLS section below covers protocol-arrived bytes.
- Exponent `e = 2` is a legal but unusual RSA public exponent. It is used here
  to make the chosen-byte construction exact and deterministic. A real peer
  chain with this exponent has not been built or served.
- The overwritten neighbour is the CRL verifier's separate static buffer at
  +576; nothing in this harness dereferences it after the write. No pointer
  control, control-flow hijack, benign marker execution or command execution
  is claimed. Rung 5 is not attempted.
- Plain-build `.bss` layout is specific to this clang 18 `-O0 -no-pie` build;
  no claim is made about other compilers, optimiser levels or embedded link
  scripts.

## Remaining gaps

TLS-protocol reach is measured on the in-process RAM transport; host-socket
loopback is structurally unavailable in the pinned tree (no driver) and needs
a new NetX-to-Linux socket/TUN driver — a separate piece of work. No pointer
control, control-flow hijack, benign marker execution, command execution or
witness replay is in hand, so rung 5 is not attempted and no ESTABLISHED claim
is made.


## TLS-protocol path (wake W1 continued, 2026-11-22 ~02:0xZ)

The pinned tree has **no host-network driver**: `ports/linux/gnu/` is a port
header plus an empty CMake target; the available transports are the in-process
RAM driver and a libpcap raw-Ethernet driver that cannot carry traffic on
Linux `lo`. The fixture has no private key, so an external openssl peer cannot
present it. A host-socket loopback path therefore does not exist in this tree
without writing a new driver — recorded as a structural negative.

The reachable step above the direct call is an in-process TLS handshake.
`harness/tls/tls_ram.c` is the upstream
`samples/demo_netx_secure_tls.c` with one change to the server's identity: it
sends the same real 8192-bit DER from the fixture. Two NX_IP instances talk
over `_nx_ram_network_driver`; `NX_SECURE_ALLOW_SELF_SIGNED_CERTIFICATES`
makes the self-signed remote certificate verify against itself. The client
thread faults under ASan with the full protocol stack intact:

`nx_secure_tls_session_start` → `nx_secure_tls_handshake_process` →
`nx_secure_tls_session_receive_records` → `nx_secure_tls_process_record` →
`nx_secure_tls_client_handshake` → `nx_secure_tls_process_remote_certificate`
→ `nx_secure_tls_remote_certificate_verify` → `nx_secure_remote_certificate_verify`
→ `nx_secure_x509_certificate_chain_verify` → `nx_secure_x509_certificate_verify`
→ `_nx_crypto_method_rsa_operation` → `_nx_crypto_rsa_operation` →
`_nx_crypto_huge_number_extract` → `global-buffer-overflow WRITE of size 1`,
0 bytes after `decrypted_signature`. Full stack in
`harness/tls/run-vuln.txt`.

Controls, same harness and build flags:

- pinned **fixed** tag (`harness/tls/run-fixed.txt`): no ASan report; the
  oversized certificate never completes verification.
- **safe input on the vulnerable build** (`harness/tls/run-vuln_safe.txt`):
  the server presents the sample's ordinary 2048-bit certificate; the client
  prints `REMOTE_CERT_CALLBACK len=702`, proving remote Certificate processing
  and verification completed, with no ASan report.
- `bash harness/tls/run.sh` rebuilds and replays all three in ~3 min.

This is a network-protocol-arrived Certificate message, not a direct call, so
wire reach at the TLS protocol layer is MEASURED. It is **not** host TCP
loopback: the transport is the in-process RAM driver, and no rung-5 claim is
made. Witness replay #1262 (W2) returned ESTABLISHED at this scope.

## Chosen-byte certificate over the TLS path (wake W3, 2026-11-22 ~03:5xZ)

W1's honesty gap was that the chosen-byte operands were set by `manual` mode and
written into harness buffers with gdb `restore`, not read from a certificate.
W3 closes that gap at the TLS protocol layer: the server now serves a DER
certificate whose own modulus, exponent and signature carry the W1
construction, and the client reaches the same write through the full TLS
handshake.

`harness/tls/gen-crafted-cert.py` patches the pinned 8192-bit fixture in place
with identical DER lengths (no TLV length fields change):

- modulus -> `n = s² − T`, where `s = 0x40 || ff*511` and `T` is a fully chosen
  1024-byte buffer with `T[0]=0x01` and `T[512:520]=deadbeefcafebabe`;
- exponent -> `e = 2`;
- signature -> `s`, left-padded to the original 1024-byte BIT STRING field.

Because `s² = n + T` and `T < n`, `s^e mod n = T` exactly. `tls_ram.c` selects
the generated array under `-DCRAFTED_CERT`; no library source is modified.

Observed:

- Vulnerable build, crafted cert, ASan: `global-buffer-overflow WRITE of size
  1`, 0 bytes after `decrypted_signature[512]`, through the full TLS stack
  (`_nx_secure_tls_process_remote_certificate` ->
  `_nx_secure_x509_certificate_verify` -> `_nx_crypto_huge_number_extract`,
  `nx_crypto_huge_number.c:1783`). Evidence
  `harness/tls/run-vuln_crafted_asan.txt`.
- Plain vulnerable build, gdb break immediately after the RSA operation
  (`nx_secure_x509_certificate_verify.c:270`), with parsed fields printed
  (`modulus_length=1024`, `exponent_length=3`, `sig_length=1024`): offsets
  504..511 are zero and offsets 512..519 are `de ad be ef ca fe ba be`. The
  adjacent global `generated_hash` begins exactly at +512 and holds the chosen
  bytes. Evidence `harness/tls/run-vuln_crafted_a_plain-gdb.txt`.
- Run B changes only the DER marker to `5a...`; the observed output changes in
  exactly that byte at +512 (`de` -> `5a`), with +511 and +513..+519 unchanged.
  Evidence `harness/tls/run-vuln_crafted_b_plain-gdb.txt`.
- Pinned fixed build with the crafted cert: no ASan report; the certificate is
  rejected before verification and the handshake stalls (20 s timeout). This is
  consistent with the existing fixed control but weaker than a clean pass; it
  is recorded as such.

Honest boundary: still RAM transport, not host TCP loopback. The certificate is
synthesised offline by the harness rather than generated by a live attacker
peer, and `e = 2` remains an unusual exponent. No pointer control, marker
execution, command side effect or rung 5. `bash harness/tls/run-crafted.sh`
regenerates the header, rebuilds and replays A, B and the fixed control.

Grade unchanged: rung 4 MEASURED, now with chosen bytes at a chosen offset
carried by a TLS-protocol-arrived certificate. No rung 5.