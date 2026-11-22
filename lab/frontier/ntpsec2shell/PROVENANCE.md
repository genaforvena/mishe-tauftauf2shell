# PROVENANCE — ntpsec2shell (frontier W121, 2026-11-22)

## Claim and pins

- CVE-2026-121506, GitLab CNA, published 2026-11-03; GHSA mapping not present
  in the CVE record. Advisory:
  `https://cveawg.mitre.org/api/cve/CVE-2026-121506`).
- Vulnerable tag `NTPsec_1_2_4` = `a9e66af44c0be47e8e32a972b3f3fb7cea65f808`.
- Fixed tag `NTPsec_1_2_5` = `42b5703303c8c7e6513f3a119cfab670924dd7be`.
- Fix commit `0a36941e499d533dfbc3fb6b1fcd8c367679d719`.

## Downloaded pinned blobs (read-only provisioning)

All from `https://gitlab.com/NTPsec/ntpsec/-/raw/NTPsec_1_2_4/...` unless noted:

- `pins/nts_extens-vuln.c` — `ntpd/nts_extens.c` at 1.2.4.
- `pins/nts_extens-fixed.c` — `ntpd/nts_extens.c` at 1.2.5.
- `pins/nts-vuln.c` — `ntpd/nts.c` at 1.2.4 (verbatim `ex_next_record()` and
  `next_uint16()` helpers).
- `pins/nts.h-vuln.h` — `include/nts.h` at 1.2.4 (`NTS_CRITICAL` value).
- `pins/aes_siv.c`, `pins/aes_siv.h` — bundled `libaes_siv` at 1.2.4.
- `pins/fix-0a36941e.patch` — public fix patch, 8 insertions / 4 deletions.

SHA-256 values are in `PIN_HASHES.txt`.

## Harness

- `harness/gen.py` extracts `extens_client_recv()` byte-for-byte from either
  pinned `nts_extens-*.c` into `fn.inc`, along with `NONCE_LENGTH`,
  `CMAC_LENGTH` and the two pinned buffer helpers. No pinned function body is
  edited; all structs, counters, packet construction and drivers are local
  stubs in `harness/harness.c`.
- `harness/config.h` is an empty stub for the pinned `aes_siv.c` include.
- Builds: gcc, `-O0 -g`, ASan and plain variants of both pins; real-crypto
  variants link pinned `aes_siv.c` against OpenSSL 3.0.13. The pinned decrypt
  symbol is renamed to `libaes_siv_Decrypt` in the object so the harness can
  supply either a modeled consumer or a real wrapper.
- `harness/run.sh` is the single replay entry point; it opens no sockets and
  touches only files under this directory. Two consecutive replays produced
  byte-identical PASS lines (`harness/run-final1.txt`, `run-final2.txt`).
- A clean `git archive f035109` replay of the committed directory reproduced
  the same 8 PASS / 0 FAIL and identical output hash; pinned blobs were read
  from the archive, not a live clone.
- Raw per-case output is in `evidence/`; normalized hashes in
  `EVIDENCE_HASHES.txt`.

## Boundaries

Direct call only: no ntpd process, no NTP/UDP wire, no NTS-KE handshake, no
disclosed key, no pointer control, no command execution. The ASan case's
decrypt consumer is modeled; the real-crypto case uses the pinned decryptor
with a lab-chosen key. This is rung 3 plus a scoped rung 4, not rung 5.
