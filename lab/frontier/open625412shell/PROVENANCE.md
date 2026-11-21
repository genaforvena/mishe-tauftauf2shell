# open625412Shell candidate — pin provenance

Provisioned 2026-11-21 17:14–17:17Z from primary sources only; no target
software was built or run, no external system was probed. Hashes are sha256 of
the exact bytes committed under `pins/`.

| File | Source | sha256 |
| --- | --- | --- |
| `pins/fix-2da371bc.patch` | `https://github.com/open62541/open62541/commit/2da371bcdaadeb23051635a60e38f31039af9fd8.patch` | `9262f68a7d2b43656a27bb059925923076070e94c41feb957dfd384d1204f1b5` |
| `pins/fix-bc30df3a.patch` | `https://github.com/open62541/open62541/commit/bc30df3adab5cc61383cb7e7f551bfd6f7ac160c.patch` | `1271429174c011cbd356535684b95ac2b49e3bc2135857383c10f2940545e088` |
| `pins/ua_services_subscription-1.5.4.c` | raw `https://raw.githubusercontent.com/open62541/open62541/v1.5.4/src/server/ua_services_subscription.c` | `42a59e133f098db78d2f8ca10bdc0d60957f54e6c0a5882f0d8157ea261acc9b` |
| `pins/ua_services_subscription-1.5.6.c` | raw `https://raw.githubusercontent.com/open62541/open62541/v1.5.6/src/server/ua_services_subscription.c` | `b0d6e8bc39bd6cac154e1be5f834a6ede134e6d1fe107e135580b439de9f294c` |

Claim records: MITRE CVE API `CVE-2026-126962` (published
2026-11-17T23:12:58.718Z, affected 1.5.4), GitHub advisory
`GHSA-x8hf-mwqg-74x6` (published 2026-11-18T00:33:24Z), ZDI-26-990
(2026-11-13, CVSS 8.8 `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`). Fix commits and
their dates verified via the GitHub commit API; tag containment verified via
the GitHub compare API (`2da371bc...v1.5.6`: `ahead`, `behind_by 0`). The fix
loop is present in pinned 1.5.6 source at `:629` and absent in pinned 1.5.4.
