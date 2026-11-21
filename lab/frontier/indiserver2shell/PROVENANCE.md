# Provenance — indiserver2shell harness

All source bytes below were fetched read-only from the official upstream
GitHub repository (`indilib/indi`) as provisioning. No external system was
probed; no daemon was run. Fetch date 2026-11-21.

## Pins

- **Affected**: the fix commit's parent `3220880734c8` (the commit the fix was
  applied to; the advisory also names `v2.2.4` / commit `3371faeb` as affected
  and `2.2.4.2` as the last affected release). Files:
  - `libs/indicore/lilxml.cpp`, `libs/indicore/lilxml.h`,
    `indiserver/MsgQueue.cpp`
- **Fixed**: fix commit `96bbd7f564bbb128a129019e44eadd40dd49cff9`
  ("Fix stack buffer overflow in lilxml error formatting (CVE-2026-71979)
  (#2473)", authored 2026-08-14). Files:
  - `libs/indicore/lilxml.cpp`, `libs/indicore/lilxml.h`

## Raw URLs

- `https://raw.githubusercontent.com/indilib/indi/3220880734c8/libs/indicore/lilxml.cpp`
- `https://raw.githubusercontent.com/indilib/indi/3220880734c8/libs/indicore/lilxml.h`
- `https://raw.githubusercontent.com/indilib/indi/3220880734c8/indiserver/MsgQueue.cpp`
- `https://raw.githubusercontent.com/indilib/indi/96bbd7f564bbb128a129019e44eadd40dd49cff9/libs/indicore/lilxml.cpp`
- `https://raw.githubusercontent.com/indilib/indi/96bbd7f564bbb128a129019e44eadd40dd49cff9/libs/indicore/lilxml.h`

## Advisory / fix references

- CVE record: `https://www.cve.org/CVERecord?id=CVE-2026-71979`
- OSV: `https://osv.dev/vulnerability/CVE-2026-71979`
- Upstream report: `https://github.com/indilib/indi/issues/2472`
- Fix commit: `https://github.com/indilib/indi/commit/96bbd7f564bbb128a129019e44eadd40dd49cff9`
- VulnCheck advisory:
  `https://www.vulncheck.com/advisories/indi-indiserver-stack-buffer-overflow-via-xml-tag-parsing`

## SHA-256 of the stored pinned files

```
06b9de6dc825086f2808032898760f3360779299a6ba9bbce3f7410d1cdfc794  src/vuln/MsgQueue.cpp
c0cbf921de2347f0dfdee8948c8c676aa61cd2d64865cb5529978214a060b653  src/vuln/lilxml.cpp
0889007a3ce308a05f0e8bf59f8853b081f9a518e0470607658f69902556af6e  src/vuln/lilxml.h
f46b998d5f3f5c9342868d573f60af1e8bcb0f4feb7c565d880b7b11b1ca0194  src/fixed/lilxml.cpp
0d69647343a98f7b8c12835b2c872790e972846d3a98221567510f2b2a471de9  src/fixed/lilxml.h
```

`run.sh` rechecks these hashes from `src/` on every replay.

## What is verbatim and what is harness

- `src/vuln/lilxml.cpp`, `src/vuln/lilxml.h`, `src/vuln/MsgQueue.cpp` and
  `src/fixed/lilxml.cpp`, `src/fixed/lilxml.h` are byte-exact upstream files;
  nothing in them was edited. The vulnerable unchecked `sprintf` is at
  `lilxml.cpp:1281`, the caller's `char err[1024]` is at `MsgQueue.cpp:525`.
- `driver.cpp` is harness-only. It calls the real `parseXMLChunk()` with a
  1024-byte caller buffer. Its `Frame.tail[512]` is a harness stack object
  that records the bytes the upstream `sprintf()` writes past `err[]`; it is
  not part of upstream and is the instrumented observation surface for rungs
  2 and 4. The ASan mode uses a standalone `err[1024]` so the sanitizer
  instruments it with redzones.

## Replay

```
bash lab/frontier/indiserver2shell/run.sh <outdir>
```

gcc/g++ 13.3.0, `-O0 -g -fno-stack-protector`, ASan on the middle build.
No network sockets are opened; the PoC packet is built in memory.
