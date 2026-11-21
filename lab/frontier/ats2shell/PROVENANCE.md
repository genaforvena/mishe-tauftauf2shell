# ATS2Shell candidate — pin provenance

Provisioned 2026-11-21 ~18:16Z from public primary sources only. No target
software was built or run, no traffic sent, no external system probed. Digests
are sha256 of the exact bytes in `src/`, also recorded in `src/SHA256SUMS`.

| File | Source | sha256 |
| --- | --- | --- |
| `src/trafficserver-10.1.3.tar.bz2` (vulnerable) | `https://downloads.apache.org/trafficserver/trafficserver-10.1.3.tar.bz2` | `b92302005fbd79c3918b97c8546471b988ce0a11dc99a2d39ba092bec45d843a` |
| `src/trafficserver-10.1.4.tar.bz2` (fixed) | `https://downloads.apache.org/trafficserver/trafficserver-10.1.4.tar.bz2` | `47f09c65a3de70db38990124834f292081520e3290a7e781898291019b6f9d9f` |
| `src/trafficserver-10.1.3.tar.bz2.sha512` | `https://downloads.apache.org/trafficserver/trafficserver-10.1.3.tar.bz2.sha512` | `8962510199f20438f45a84e688d7e2cf113058f9aa274f811025480a51531705` |
| `src/trafficserver-10.1.4.tar.bz2.sha512` | `https://downloads.apache.org/trafficserver/trafficserver-10.1.4.tar.bz2.sha512` | `afa085be90be2a3a21a595ed3f6e0d45d614ffb79c748c1aaa2db4a723b5e216` |
| `src/fix-f4561a94.patch` | `https://github.com/apache/trafficserver/commit/f4561a945ac52010a598e0cd19b12d058044c3d2.patch` | `6a6626f89f4255beee82b900a1ad35aa8150862ded9dedcd92cedd396e178092` |

`sha512sum -c` on both published sidecars: 2/2 OK (published digests
`6f5dd78a…5733ea8` for 10.1.3, `31808a60…794d3b361b3c0f` for 10.1.4).
`sha256sum -c src/SHA256SUMS`: 5/5 OK, re-run before handoff.

Claim records read this wake: MITRE CVE API `CVE-2026-58154` (CNA Apache,
published 2026-07-29T08:24:02.078Z, updated 2026-10-01T16:58:40.837Z, CWE-787,
CVSS 3.1 8.9 `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:H`), vendor page
`https://trafficserver.apache.org/security-2026-07.html` ("34 security
vulnerabilities"), oss-sec `/2026/q3/338` (upgrade to 9.2.15 / 10.1.4), and
CVE reference `https://lists.apache.org/thread/5prl9glcm9g2swnq9hqxvnokylm1gr6d`.

Fix provenance: master commit `f4561a945ac52010a598e0cd19b12d058044c3d2`
("Fix out-of-bounds write in MIME obs-fold handling", +49/−3 in `MIME.cc` and
`unit_tests/test_Hdrs.cc`); 10.1.x commit
`5642692b888fcc9cf26a43ec2f39a05f938c4963`; GitHub compare API
`5642692b…...10.1.4` reports `status: ahead`, `ahead_by: 128`, `behind_by: 0`,
merge base equal to the fix commit — the fix is an ancestor of tagged 10.1.4
(`f8be6725daee427fbf88f166f14b10cb5525b220`).

Raw pinned-byte verification: only `src/proxy/hdrs/MIME.cc` was extracted from
each tarball, into `check-10.1.3/` and `check-10.1.4/`. Vulnerable 10.1.3 has
the decrementing obs-fold walk at `:2427–2432`; fixed 10.1.4 has the guarded
form plus the accumulated-line fallback at `:2477–2484`. The 9.2.x line uses
the legacy path `proxy/hdrs/MIME.cc`; raw GitHub reads show the same vulnerable
form at 9.2.14 and the same fixed form at 9.2.15 (scout's earlier "9.2.x has no
unfold code" claim was a wrong-path artifact, corrected here). The two 9.2.x
files were read from GitHub raw only, not pinned as tarballs.
