# Provenance — ConnMan `get_domains()` (CVE-2026-115863)

## Provisioning

Read-only fetches on 2026-11-22. No probe, scan or connection to any external
target; all runtime work is local, direct-call, no network.

- Advisory: `https://github.com/advisories/GHSA-725f-6r9j-c4hf`
  (CVE-2026-115863, published 2026-10-23, HIGH 7.6, CWE-121 stack-based buffer
  overflow). Claim source: NVD via GitHub Advisory Database.
- Vulnerable release pin: ConnMan tag `2.0`,
  `https://git.kernel.org/pub/scm/network/connman/connman.git/plain/gdhcp/client.c?h=2.0`.
- Introducing commit: `bb06c47101ca24` ("gdhcp: Domain search list DHCPv6
  option is checked").
- Fix: Andrei Miu's patch posted to the connman list on 2026-10-23, preserved
  verbatim in Debian bug #1153442 (`https://mail-archive.com/debian-bugs-dist@lists.debian.org/msg2132485.html`).
  The mail archive rendering drops one trailing context line; the saved patch
  restores that line so the hunk applies cleanly to the pinned tag-2.0 source.
  **No upstream fix commit exists**: Debian reports upstream HEAD `9e46e4a0`
  still carries the vulnerable function; there is no tagged fixed release.
  The "fixed" source below is the tag-2.0 snapshot with that posted hunk
  applied, not a vendor release.

## Saved pinned bytes (SHA-256)

```
722cccc072d658f6c9fded507e1deab8cd8a8837479c9215c88a4834f81fcb0f  src/client-2.0.c
d252cf019c960a3a9a60501429155cead2876269c79ab1cca7443b787f3c5c0e  src/client-2.0-fixed.c
a9715aa5c7e757baa0afa0041e29e988f2e0500788697a4ed89b7d5528c49aa2  src/fix-miu-20261023.patch
3c24f1b659c610e8ba2231cb1f76bc564c2620252bf0bea57b2e142a5d59de4f  harness/driver.c
090d8ea201196ea32892c95aaeb38d5b2a99c9a8ef41c4d081782b8a6f60a5c2  vulnerable get_domains() slice
466360babe68e0cdf7abfa8d5e20c5dd7ad7bea05631ecf0f39f8f531241b0d9  fixed get_domains() slice
```

`run.sh` asserts all four full-file hashes plus both verbatim function slice
hashes on every invocation. Slices are extracted with
`sed -n '/^static GList \*get_domains/,/^}/p'`; the function body is never
retyped or patched. `driver.c` supplies only `NS_MAXDNAME`, four GLib stubs and
the crafted DOMAIN_LIST value.

## Toolchain and result

gcc 13.3.0 (`gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`) and clang 18.1.3
(`Ubuntu clang version 18.1.3 (1ubuntu1)`), `-g -O0
-fno-omit-frame-pointer -fsanitize=address` for ASan variants; the plain
canary variant is compiled without ASan. 61 PASS / 0 FAIL on three consecutive
runs, path-independent normalized content hash
`bf6810e7c0d3db2fa2bae36e7233974e6fd593084c209952e742df1e3a48211f`.

## Instrumentation boundary

- No ConnMan build, no `g_dhcpv6_client_*` call path, no DHCPv6 socket, no
  daemon, no network.
- One direct call to the verbatim pinned `get_domains(maxlen, value)` with a
  synthesised DOMAIN_LIST value: 2048 bytes, every byte `0xff` except
  `value[1024] = K`. The last in-bounds label byte K is attacker-chosen.
- ASan traps the **read** half of the `while (c && *c)` / `*c = '.'`
  read-modify-write at the first out-of-bounds step: gcc reports `dns_name` at
  frame `[48, 1074)` and the access at frame offsets 1089/1105/1137/1201 for
  K=0x10/0x20/0x40/0x80 (deltas 15/31/63/127); clang reports `[32, 1058)` and
  offset 1185 for K=0x80 (delta 127). The delta is `K - 1` on both compilers.
- The **store** half is observed in the plain build: a 16384-byte caller-stack
  region prefilled `0xEE` receives 69 deterministic `0x2E` ('.') writes at
  offsets 49 through 16301 for K=0x80, on three consecutive runs.
- Fixed snapshot and a well-formed safe DOMAIN_LIST (two short labels plus a
  terminator) produce clean lists with no ASan report.
- No natural stack layout of the real connmand caller, no adjacent object
  identity, no pointer control, no marker, no command, no rung 5.
