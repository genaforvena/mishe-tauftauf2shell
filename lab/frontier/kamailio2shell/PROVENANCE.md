# Provenance — Kamailio alias port overflow (CVE-2026-106803)

All references below were fetched read-only on 2026-11-21 as provisioning.
There was no off-loopback exploit probe: the harness is a set of local
processes and never opens a socket. Only the public advisory and source
endpoints listed here were contacted to pin bytes.

## Advisory and metadata

- OSV / CVE record: `https://api.osv.dev/v1/vulns/CVE-2026-106803`
  (CNA MITRE, published 2026-11-02, CVSS 3.1
  `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, CWE-121).
- CVE source record:
  `https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/106xxx/CVE-2026-106803.json`
- Upstream report: `https://github.com/kamailio/kamailio/issues/4954`
- Fix PR: `https://github.com/kamailio/kamailio/pull/4958`
- Fix commit: `https://github.com/kamailio/kamailio/commit/21261436492f0014930e804e20586e3833bb91b9`
  (author kaelyn ke, 2026-09-25, subject
  `ims_registrar_pcscf: check for port size in alias param`).
- Claim / PoC gist:
  `https://gist.github.com/hackeryounow/7d7ccc9ec501a5d8c9143b2e1bcc11cb`
  (created 2026-10-31, updated 2026-11-02; text only, no exploit code).
- The fix commit itself cites sibling upstream fix `57794cd142` in
  `ims_ipsec_pcscf` as the precedent.

## Pinned source bytes (SHA-256)

| file | source | sha256 |
|---|---|---|
| `src/notify.c.6.1.4` | `https://raw.githubusercontent.com/kamailio/kamailio/6.1.4/src/modules/ims_registrar_pcscf/notify.c` | `4c845f297cb7f2ef8f8b9979c589f23724f7bfcf27708ddc72b589994e442059` |
| `src/save.c.6.1.4` | `https://raw.githubusercontent.com/kamailio/kamailio/6.1.4/src/modules/ims_registrar_pcscf/save.c` | `9dee618a7fe265ae8adc8df207f51427bf5b48a479d5159f4916d6d1f387e867` |
| `src/fix-21261436492f.patch` | `https://github.com/kamailio/kamailio/commit/21261436492f0014930e804e20586e3833bb91b9.patch` | `fafbea2d7f15ddbfa075ef06fb7fda3f0c59b4d71951a72bd0bad8081963e413` |
| `src/notify.c.6.1.5` | `https://raw.githubusercontent.com/kamailio/kamailio/6.1.5/src/modules/ims_registrar_pcscf/notify.c` | `60018c6519f94ba9e69a0323c72ea6df2bcf721b7c5dd656f4f202d3b03e3eda` |

`6.1.5` is the pinned fixed release: it declares `char bufport[6]` at
`notify.c:91` and rejects `received_port_len >= sizeof(bufport)` at
`notify.c:174`. `6.1.4` declares `char bufport[5]` at `notify.c:91` and has no
check.

## Harness bytes

| file | sha256 |
|---|---|
| `alias_overflow.c` | `5a19049f7a082ad959da66fff698e03ce6cc8f7d08a16659ac10bd687563744a` |
| `run.sh` | `958d2a94a47d77dd095b7abf7dc887dd5bcffba45cce687743ff28f62c94a65b` |

## What is pinned and what is reconstructed

Pinned: affected release bytes (`6.1.4`), fixed release bytes (`6.1.5`),
the exact fix patch, the affected/fixed version range, the fix commit, the
advisory with CVSS/CWE, and a public claim/PoC text.

Reconstructed / instrumented: the extracted harness reproduces the alias
branch of `process_contact()` and the two vulnerable copy statements, but not
Kamailio's `parse_uri()`, `libxml` reginfo parsing, `ims_usrloc_pcscf` calls,
real `ims_registrar_pcscf` module configuration or the real stack layout.
The `neighbour` region and the chosen function pointer are instrumentation:
they stand in for adjacent frame state so chosen-byte control is observable.
No live Kamailio process was built or run this wake.
