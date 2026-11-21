# Provenance — asn1scc CVE-2026-75614 harness

All sources below were fetched read-only on 2026-11-21 ~13:27Z from the named
public endpoints (provisioning only; no probe of any external system). Their
SHA-256 digests are recorded in `src/SHA256SUMS` and checked by `run.sh` before
anything is built; a mismatch exits 2 with no drivers generated.

| Pin | Source | SHA-256 |
| --- | --- | --- |
| `cve-cve-2026-75614.json` | `https://cveawg.mitre.org/api/cve/CVE-2026-75614` | `7cf579101f3bda7cd0ed9e431191869bb6fe2f748b657699244816e104578d69` |
| `ghsa-825c-7h77-2jjq.html` | `https://github.com/esa/asn1scc/security/advisories/GHSA-825c-7h77-2jjq` | `f9e60045b35afa7592a8bae6dfec8a557848877bdb2ca847cb2a5e9b24c516f3` |
| `osv-cve-2026-75614.json` | `https://api.osv.dev/v1/vulns/CVE-2026-75614` | `a6c69e44f3eb6b4aaf652b3cae962036945a18183f2cc01b8d4441d341fb938c` |
| `release-4.7.0.1.json` | `https://api.github.com/repos/esa/asn1scc/releases/tags/4.7.0.1` | `7899c50a5079ba9512cd6fe2ba58f4c6e72dc49037dd3494a6d00e05b0402473` |
| `fix-fe6ab763.patch` | `https://github.com/esa/asn1scc/commit/fe6ab763bc60d8a2def4104c15414809b45fffd9.patch` | `7780f90f9c6f2ca3f71edd617a90190780fd88ddd4557e50a0562bd9767fd8d4` |
| `asn1scc-4.6.0.17.tar.gz` | `https://codeload.github.com/esa/asn1scc/tar.gz/refs/tags/4.6.0.17` | `2001269db4d5d290793315cf78cb84f953dfb2d5a3d1d9fc2fd86ad4c57bec22` |
| `asn1scc-4.7.0.1.tar.gz` | `https://codeload.github.com/esa/asn1scc/tar.gz/refs/tags/4.7.0.1` | `3da3f8fdf1a6cee08c18367e542d877039d42e9e55b2daa3c26accc09fbab8dd` |
| `asn1scc-bin-4.7.0.1.tar.bz2` | `https://github.com/esa/asn1scc/releases/download/4.7.0.1/asn1scc-bin-4.7.0.1.tar.bz2` | `621b4f8269f02ef8d9355f5b4328705b47dfbf4edea83c30bad95b306787a538` |

The GHSA HTML pin carries GitHub's rotating nonce/request-id/visitor metadata;
treat it as a byte snapshot of the advisory text, not a reproducible byte-for-
byte fetch. The CVE/OSV JSON, fix patch, both release tarballs and the compiler
asset are byte-stable on re-fetch at the time of writing.

## Verbatim components

- `run.sh` extracts the two pinned source tarballs with `--strip-components=1`
  into fresh directories and compiles every `asn1crt/*.c` from the chosen
  version verbatim. Neither runtime tree is edited, copied into the harness or
  patched at build time.
- The pinned 4.7.0.1 release compiler asset generates `schema.c` / `schema.h`
  from the harness-authored `schema.asn` (`OCTET STRING (SIZE(0..5))`) in a
  fresh output directory on every run. Both builds use the *same* generated
  decoder; only the pinned C runtime differs. Expected generated digests:
  `schema.c` `0af4d8696ca11e2114cc80e1efcd5f0be79c97f3a0fc9bb490936fe7ce13bff1`,
  `schema.h` `0ccd6f32aca81c6a6ec20ab1eee99d5a85f39440c189cea8fa4b504d8b7ae69e`.
- `driver.c` is harness-authored. It builds the 8-byte wire packet (3-bit
  over-range length field plus seven packed chosen payload bytes), attaches it
  to the runtime's `BitStream`, and calls the generated `Payload_Decode()`.
  No harness shim performs the OOB store; the pinned `BitStream_ReadByteArray`
  does.

## Harness stand-ins and labels

- The ASan/plains modes allocate exactly 9 bytes (`sizeof(int)` + the schema's
  5-byte array) for the destination. This removes C struct padding so the
  first past-end store lands in the ASan redzone; it changes placement, not
  the decoder or the write length.
- `readback` mode stages the same object at the start of a 32-byte region
  prefilled with `0xcc` and prints the bytes at `+5`/`+6`. Those two bytes are
  harness staging, not an identified live application object: rung 4 is
  INSTRUMENTED chosen bytes at chosen offsets, not neighbour control.
- `guard` mode places `arr[5]` exactly at a `PROT_NONE` page boundary using a
  private anonymous `mmap`; it records the first past-end store only.
- No ASN.1-speaking application, uPER receiver, socket, listener, real heap
  neighbour, pointer, control-flow diversion or execution was observed.
  All of those remain UNKNOWN.

## Build and replay

`bash run.sh <absolute-outdir>`: verifies pins, extracts, regenerates, builds
four local binaries (two ASan, two unsanitized), runs the checks and prints
`TOTAL PASS=12 FAIL=0` plus two five-run digests. Normalized trace lines carry
only fields, values and verdicts — no PID, address or path text — so replays
are byte-identical.
