# libgsf2shell lab provenance (screening only)

- Claim: CVE-2026-116124, CNA VulDB, "GNOME libgsf OLE2
  `gsf-infile-msole.c ole_info_read_metabat` heap-based overflow". CVE record
  <https://www.cve.org/CVERecord?id=CVE-2026-116124>, OSV
  <https://api.osv.dev/v1/vulns/CVE-2026-116124>, OSV FIX reference
  <https://gitlab.gnome.org/GNOME/libgsf/-/commit/a8e25560b74f84c3f86df6ca0ac59195fa5af68a>.
- Vulnerable source: `libgsf-1.14.59.tar.xz`, SHA-256
  `0d03cb6fadfe735caa13498a024ccd8fdb6cab77df6d9d283a64410c96f2fa49`,
  fetched 2026-11-24 from
  <https://download.gnome.org/sources/libgsf/1.14/libgsf-1.14.59.tar.xz>.
- Fixed source: `libgsf-1.14.60.tar.xz`, SHA-256
  `83e12c36a099a8a7019bf425e2c24af66eeb2ef5874251e694431a07d9805dae`,
  fetched 2026-11-24 from
  <https://download.gnome.org/sources/libgsf/1.14/libgsf-1.14.60.tar.xz>.
  Its `NEWS` and `gsf/gsf-infile-msole.c` already contain the fix, contrary
  to the CVE record's affected-through-1.14.60 list.
- Pin patch: `pinned/fix-a8e25560.patch`, SHA-256
  `667abb3711075dc2d3715f483e1931f42760592e7d4dd403b5fec57f8c20dc69`,
  fetched from the GitLab commit `.patch` endpoint (the HTML commit page
  serves a client challenge on this host).
- Pin vulnerable/fixed source copies: `pinned/gsf-infile-msole-v1.14.59.c`
  SHA-256 `077523f7adaad4939b1df3622b1a56e628ae791fa2741ed8d74d601732a8e432`,
  `pinned/gsf-infile-msole-v1.14.60.c` SHA-256
  `6865015429c2c322eb3351e13e6f4667531ea3f13b46a2e57c65d9ca2190da69`.
- No build was run, no OLE2 file was crafted and no ASan observation exists.
  The screening rests on source arithmetic in the pinned files: the 16 GiB
  file-size floor is documented in `reports/frontier-libgsf2shell.md`.
  No external probes; all fetches were read-only source provisioning.
