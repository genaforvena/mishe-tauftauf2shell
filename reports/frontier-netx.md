# frontier — NetX Secure X.509 unbounded RSA modulus (netx2shell)

Status: **ADMITTED 2026-11-22 ~01:4xZ as `netx2shell` under standing
approval #6.** Rung 3 observed on the real pinned library with the real
upstream 8192-bit DER fixture; wire reach and rung 4 UNKNOWN, no rung 5.
The operator adopted frontier's staged two-pane window 75, charter, seed wall
and registry entry, and added the 70th wake route. Witness replay required
for any published claim; none in hand at admission.

## Verified ground truth

- Claim source: GHSA-rcv5-vfff-25gh, published 2026-10-02 by the finder,
  and NVD CVE-2026-93475. Both reached as read-only provisioning.
- Severity as claimed: critical 9.8,
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, CWE-787 + CWE-1284.
- Affected: NetX Duo (Eclipse ThreadX) `<= 6.5.1.202602`. Patched:
  `6.5.2.202603`. Fix commit `4adb237093c1f578c876e28c3752affaaf159ee0`.
  Tags and archive hashes in `lab/frontier/netx2shell/PROVENANCE.md`.
- Claimed primitive: an X.509 certificate carrying an RSA modulus larger than
  `NX_CRYPTO_MAX_RSA_MODULUS_SIZE` (4096 bits) drives an out-of-bounds write
  past the 512-byte file-scope `decrypted_signature[]` during ordinary chain
  verification. Pre-auth: the peer supplies the oversized key in its own
  chain; the issuer lookup checks the remote store before the trusted store.
  Written bytes are `s^e mod n` with signature, exponent and modulus chosen by
  the attacker. An 8192-bit key overruns by 512 bytes; the `USHORT` DER length
  admits roughly 64 KiB.
- Claimed reach: TLS/DTLS clients verifying a malicious server chain, and
  servers doing client-certificate authentication.

## Source-bound mechanism (from the pinned bytes and the fix hunk)

1. `_nx_secure_x509_extract_oid_data` copied the modulus length straight from
   the DER into a `USHORT`, with no upper bound (only an underflow guard).
   The vulnerable release parses the real 8192-bit fixture cleanly: observed
   `parse_status=0 modulus_bytes=1024`.
2. `_nx_secure_x509_certificate_verify` passes the issuer's RSA modulus to
   `_nx_crypto_method_rsa_init` and the issuer's *exponent* to
   `_nx_crypto_method_rsa_operation` as `key` / `key_size_in_bits`. The RSA
   operation's one output-size check compares `output_length_in_byte` (512)
   against `key_size_in_bits >> 3` — typically 3 bytes for the exponent —
   so it passes.
3. The real write is `_nx_crypto_huge_number_extract(&output_hn, output,
   modulus_length, &mod_length)` at `crypto_libraries/src/nx_crypto_rsa.c:147`.
   Its guard is against the same attacker-controlled `modulus_length`, not
   the destination capacity. The destination is `decrypted_signature[512]`
   in `nx_secure/src/nx_secure_x509_certificate_verify.c:28`.
4. Fix hunks: `_nx_secure_x509_extract_oid_data` refuses a modulus above
   `NX_CRYPTO_MAX_RSA_MODULUS_SIZE` and refuses an INTEGER with no leading
   byte; `_nx_crypto_method_rsa_init` independently refuses
   `key_size_in_bits > NX_CRYPTO_MAX_RSA_MODULUS_SIZE`. Upstream added a
   regression test using the same real 8192-bit certificate.

## Local experiment actually run

Direct-call harness on the real pinned library with the real upstream
8192-bit DER fixture (details in `PROVENANCE.md`; clang 18.1.3 + ASan):

- Affected `v6.5.1.202602_rel`: parser accepts cert, 1024-byte modulus
  recorded; `_nx_secure_x509_certificate_verify` → RSA operation → ASan
  `global-buffer-overflow`, `WRITE of size 1`, 0 bytes after
  `decrypted_signature` (512 bytes). Full stack in `out-vuln-der.txt`.
- Fixed `v6.5.2.202603_rel`: same bytes give `parse_status=418`
  (`NX_SECURE_X509_INVALID_CERTIFICATE`), `modulus_bytes=0`, `verify_status=131079`,
  no ASan report.
- Synthetic 0x9c-modulus control on both versions: no write; preserved as a
  negative control, not evidence.

This is **rung 3**: confirmed memory corruption, observed on the real code,
not a crash-only claim. The harness substitutes only the hash method (NULL
ops); it does not substitute the parser, the verifier, the RSA method or the
huge-number extract where the write occurs.

## Honest rung-4 feasibility

- Not attempted this wake: a plain (non-ASan) build that dumps the real
  neighbouring `.bss` bytes after `decrypted_signature` to show attacker-chosen
  bytes at a chosen offset. The ASan run proves the write and its content path
  (`s^e mod n`), but the *placed-byte* claim is not yet observed, so rung 4 is
  UNKNOWN, not inferred.
- Recoverable ASan redzones must not be treated as adjacent-object control.
- Wire reach is UNKNOWN. Our evidence is a direct call into the real library,
  not a TLS/DTLS handshake; there is no loopback server, no crafted
  Certificate message, no observed network-triggered fault. The advisory's
  pre-auth claim is a claim to be reproduced.
- No rung 5. No command execution, no benign marker, no live target.

## Cheapest next experiment to move up a rung

1. Wire rung 3/4: build a loopback TLS client against the pinned vulnerable
   NetX Secure, present the real 8192-bit certificate as the server chain,
   confirm the same ASan frame from a network-arrived Certificate message.
   This is the decisive experiment — it upgrades wire reach from UNKNOWN.
2. Rung 4: plain build, print the real `.bss` neighbours of
   `decrypted_signature` before and after verification with two signatures
   differing in one chosen byte; show the chosen byte at the chosen offset
   with neighbours unchanged.
3. Fixed-version and safe-input controls already pass for the direct call;
   repeat them through the wire path.

## Why ranked tractable

Open source, exact affected and fixed tags pinned, small self-contained fix
with a real regression fixture, pre-auth network claim, chosen-byte content
rather than a fixed NUL. The main uncertainty is the embedded build and wire
setup, not whether the write exists. No owned target overlaps this lane
(no `netx*` charter or report before this brief).

## Operator admission (2026-11-22 ~01:4xZ)

Admitted under standing approval #6 with all five elements recorded in
`.mishe-tauftauf/charters/netx2shell.md` and `docs/task.md`: claim source
GHSA-rcv5-vfff-25gh plus NVD CVE-2026-93475; identifier CVE-2026-93475;
affected `<= 6.5.1.202602` and fixed `6.5.2.202603` tag archives (SHA-256
`31a30408…` / `f090d4e5…`) with fix commit `4adb2370…`, all three
`src/SHA256SUMS` digests recomputed 3/3 OK by the operator at admission;
primitive = an unbounded DER modulus length driving a chosen-content
`s^e mod n` write past `decrypted_signature[512]`, observed by ASan at
`nx_crypto_huge_number.c:1783` on the real pinned library with a clean
fixed-tag parse-rejection control; rung-4 plausibility = attacker-chosen
bytes but no observed placement or consumer, and direct-call evidence only,
so wire reach stays UNKNOWN. Grade at admission: rung 3 on the real library
via direct call, rung 4 and wire reach UNKNOWN, no rung 5, no witness replay.

This is an embedded TLS/DTLS library, not a web-facing server; the class
boundary is part of the admission record. The operator adopted frontier's
live two-pane window 75 (no duplicate), registered the wake-failure signal
to `operator`, added the 70th wake route, and the pinned full-flag sync
printed `written 3, removed 0`; the pinned `--no-observe` doctor read
`PASS local plant out of Git` / `GREEN`, rc 0. Frontier should leave this
status block and admission note to the operator and keep its own lane work
in its other sections.
