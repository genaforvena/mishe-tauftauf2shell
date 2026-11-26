# Provenance — openscapmangle2shell (CVE-2026-122056 / GHSA-5h6x-q65w-wxvf)

Claim sources read 2026-11-26 (read-only, no external probing):
- CVE record https://www.cve.org/CVERecord?id=CVE-2026-122056 (CNA Red Hat, published 2026-11-09)
- Upstream advisory https://github.com/OpenSCAP/openscap/security/advisories/GHSA-5h6x-q65w-wxvf
- Fix commit https://github.com/OpenSCAP/openscap/commit/5f1f2bccd4b5f85e44a21a0ce3c854fbb65a2163
- Vendor fixed control https://api.osv.dev/v1/vulns/RHSA-2026%3A103520 (not built here)

Upstream bytes: `pins/sds.c.vuln` (tag 1.4.6) and `pins/sds.c.fixed` (fix commit) were
fetched verbatim; SHA-256 in `pins/PIN_HASHES.txt`. The two harness translation units
`harness/sink_vuln.c` and `harness/sink_fixed.c` copy upstream lines 853-887 verbatim
(including tabs and comments) and use a `#line 853 "src/DS/sds.c"` directive so a
sanitizer trace names the pinned source line. Everything else in `harness/main.c`
and `run-all.sh` is frontier-authored scaffolding: a driver that selects the
advisory's href vectors and a PASS/FAIL script. No OpenSCAP build, no libxml2 and
no CLI path is used; only the sink function's libc malloc/strlen surface.

Correction to the read-only scout note: it reported the sink at sds.c:889 and
malloc at :865 for "main/1.4.6" and called the advisory's :884 wrong. The pinned
1.4.6 tag actually has the NUL at :884 and malloc at :860, matching the advisory;
the scout's numbers came from the moving `main` branch, five lines later. The
harness uses tag-1.4.6 line numbers and its ASan check asserts `src/DS/sds.c:884`.

Negative controls: `safe` vector `a/b@c` produces 7 bytes + NUL in an 8-byte
allocation. Fixed pin on both attack vectors allocates one extra byte.

No network client, loopback service, credential or off-loopback target is used
by any harness step; all runs are local files and local processes.
