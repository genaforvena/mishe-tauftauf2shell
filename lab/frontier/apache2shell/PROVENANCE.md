# apache2shell frontier pins — provenance

Fetched 2026-11-21 ~21:40Z from primary/public sources. No local build or
traffic has been run from these pins. `cd src && sha256sum -c SHA256SUMS` → 6/6 OK.

| File | Source |
|---|---|
| `src/h2_request.c.2.4.70` | `https://raw.githubusercontent.com/apache/httpd/2.4.70/modules/http2/h2_request.c` |
| `src/h2_request.c.2.4.71` | `https://raw.githubusercontent.com/apache/httpd/2.4.71/modules/http2/h2_request.c` |
| `src/fix-824beab9.patch` | `https://github.com/apache/httpd/commit/824beab9b9424d6cfb29595248fdbf6c3dddeab1.patch` |
| `src/CVE-2026-119618.json` | `https://cveawg.mitre.org/api/cve/CVE-2026-119618` |
| `src/CVE-2026-119618.osv.json` | `https://api.osv.dev/v1/vulns/CVE-2026-119618` |
| `src/README.poc.md` | `https://raw.githubusercontent.com/googlesky/CVE-2026-119618/main/README.md` (external claim, wording only) |

Verified from the tag bytes: the entire 2.4.70→2.4.71 release delta in
`h2_request.c` is one line at 2.4.70:353,
`req->headers` → `r->headers_in` inside `assign_headers()`.

The fix commit was checked against the GitHub API:
`824beab9b9424d6cfb29595248fdbf6c3dddeab1`, 2026-11-09T02:54:20Z,
message "mod_http2: assign_headers update table (#975) (#977)", touching
only `modules/http2/h2_request.c`; trunk original
`5ed39287660daacd1233cb9bbc984b25fa9a4fe3`.

All PoC behaviour (ASan/TSan differential, 79-header trigger, 8 KB
allocation race, clean 2.4.71) remains an **external claim** until replayed
locally. Ranked #1 unadmitted, rung 0. Brief: `reports/frontier-apache2shell.md`.
