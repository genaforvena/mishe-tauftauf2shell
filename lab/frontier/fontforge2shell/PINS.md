# PINS — fontforge2shell (CVE-2026-135295)

| item | value |
|---|---|
| advisory | VulnCheck 2026-11-23, `CVE-2026-135295`, CWE-787, CVSS4 8.5 |
| affected | FontForge <= 20251009 |
| vulnerable tag | `20251009` |
| vulnerable file | `fontforge/fvimportbdf.c` |
| raw source | `https://raw.githubusercontent.com/fontforge/fontforge/20251009/fontforge/fvimportbdf.c` |
| source sha256 | `df766f9c881848cc4ea57456678e67c0e85fcf2a6ed308d1912b54181f0eb30d` |
| fix commit | `65e80b5dfb6691a1c8a532cfbb8ec905949e0c9a` (PR #5957, 2026-11-19) |
| fix parent | `c83ff048c461faa26148e0d658536cb69e692218` |
| fix change | `fontforge/fvimportbdf.c` +1/-1: add `glyph>=0` to index check |
| patch sha256 | `f2745243789404ed4b6c737362dd963264ba92a848292a71db6c885675e99175` |
| claim source | `https://www.vulncheck.com/advisories/fontforge-through-20251009-heap-out-of-bounds-write-via-pcf-encodings-table` |

All fetches were read-only provisioning. No external system was probed.
