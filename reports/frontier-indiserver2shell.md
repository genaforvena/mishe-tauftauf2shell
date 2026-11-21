# indiserver2Shell — frontier brief

**Candidate:** INDI `indiserver` unbounded `sprintf()` error formatting in the
XML chunk parser, CVE-2026-71979. **Status:** local rungs 1/2/3 established on
verbatim pinned upstream `oneXMLchar()` / `parseXMLChunk()` bytes; rung 4 is
instrumented chosen-byte control at chosen offsets in the harness stack only.
No live daemon, no real TCP client and no RCE. **Ranking:** high tractability,
HIGH advisory severity (CVSS 4.0 8.7, `AV:N/AC:L/AT:N/PR:N`, no configuration
gate), but the advisory claims availability only — impact ceiling is honest.

## Verified ground truth

- CNA VulnCheck, CVE-2026-71979, published 2026-08-17, CWE-121,
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`
  (CVSS 3.1 7.5, `A:H` only). Affected `0` through `2.2.4.2`; unaffected at
  fix commit `96bbd7f564bbb128a129019e44eadd40dd49cff9`. The advisory also
  names `v2.2.4` / commit `3371faeb` as reproduced.
- Claim: `indiserver` listens on TCP/7624 with no authentication or transport
  encryption. A client sends one ~1.2 KB packet with mismatched XML tags whose
  names exceed 1024 bytes; the parser formats a diagnostic with unbounded
  `sprintf()` into a fixed 1024-byte stack buffer, terminating the daemon and
  all its client/driver sessions. The issue states plainly that no control-flow
  hijack was constructed or claimed — availability only.
- Sources: [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-71979),
  [OSV](https://osv.dev/vulnerability/CVE-2026-71979),
  [upstream issue #2472](https://github.com/indilib/indi/issues/2472),
  [fix commit 96bbd7f](https://github.com/indilib/indi/commit/96bbd7f564bbb128a129019e44eadd40dd49cff9),
  [VulnCheck advisory](https://www.vulncheck.com/advisories/indi-indiserver-stack-buffer-overflow-via-xml-tag-parsing).
  Credit: Fatullayev Asadbek (finder), @knro (fix).

## Source-bound mechanism

In `libs/indicore/lilxml.cpp:1275-1282`, the `INCLOSETAG` branch of
`oneXMLchar()` grows the closing-tag string without bound and then formats:

```c
if (isTokenChar(0, c))
    growString(&lp->endtag, c);   /* no upper limit */
else if (c == '>') {
    if (strcmp(lp->ce->tag.s, lp->endtag.s)) {
        sprintf(ynot, "Line %d: closing tag %s does not match %s",
                lp->ln, lp->endtag.s, lp->ce->tag.s);   /* no bound */
        return (-1);
```

Both `%s` values come from the client's tag names; `growString()` doubles on
demand. `ynot` is the caller's `char err[1024]` at
`indiserver/MsgQueue.cpp:525`, passed straight to `parseXMLChunk()` at `:526`
from `MsgQueue::readFromFd()` — the shared read path for every TCP client and
driver before any application processing. The read buffer is `char
buf[49152]` (`MsgQueue.hpp:36`), so the parser can assemble a much longer tag
than the 1024-byte destination.

Fix commit `96bbd7f` replaces every `sprintf(ynot, ...)` in `lilxml.cpp` with
`snprintf(ynot, XML_ERROR_SIZE, ...)` and defines `XML_ERROR_SIZE 1024` in
`lilxml.h` as the contract for every caller. It also raises several 512-byte
caller buffers in other drivers to `XML_ERROR_SIZE`; those are local-file
paths, not the remote TCP surface. Pinned file hashes and URLs are in
`lab/frontier/indiserver2shell/PROVENANCE.md`.

## Local evidence (verbatim pinned function)

Harness `lab/frontier/indiserver2shell/`. `run.sh` verifies all five pinned
hashes, compiles the **byte-exact** upstream `lilxml.cpp` from the fix parent
`3220880` (affected) and from `96bbd7f` (fixed) against one driver that calls
the real `parseXMLChunk()`. Clean replay: 19 PASS, `ALL CHECKS PASS rc 0`,
trace SHA-256
`2c446e0f1b1beecee5aa437d5a15818ad0c951d72fbcdb2cb545a656925ca85c`.

- **Rung 1** — one in-memory packet `<A*600>x</B*600>` is 1206 bytes. The
  error string is `prefix 20 + endtag 600 + middle 16 + opentag 600 + NUL =
  1237` bytes into a 1024-byte `err[]`: `expected_oob=213`. Upstream line
  numbers verified: vulnerable `sprintf` at `lilxml.cpp:1281`, caller
  `char err[1024]` at `MsgQueue.cpp:525`.
- **Rung 2** — the plain build's adjacent harness stack region records the
  overflow: `first_changed=0`, i.e. the very first byte past `err[1024]` is
  written. This is an observed write, not an assumed layout.
- **Rung 3** — ASan reports `stack-buffer-overflow`, `WRITE of size 1237`,
  with frames `oneXMLchar` at pinned `lilxml.cpp:1281` and `parseXMLChunk` at
  `lilxml.cpp:348`, and names `err` as the overflowed stack object. ASan
  redzones isolate the buffer, so no chosen-byte control is claimed from this
  run.
- **Rung 4** — the attacker-controlled opening tag carries the token-safe
  marker `INDI2SHELL` at a computed index. Requested victim offsets 0 and 64
  both read back `chosen_offset` equal to the request with byte-exact
  `chosen_bytes=INDI2SHELL`. **INSTRUMENTED only:** the victim is a harness
  stack object, no live process, no return address or useful pointer target,
  no execution.
- **Fixed control** — pinned `96bbd7f`: `first_changed=-1`, chosen bytes
  absent, rc 0 for the same 1206-byte packet.

## Rung-4 feasibility and cheapest next experiment

Feasibility: good for corruption, uncertain for control. The write is a single
large `vsprintf` with fully attacker-chosen alphanumeric bytes onto the stack,
so return-address and saved-frame overwrite is structurally plausible; the
only token-safe alphabet (letters, digits, underscore) prevents raw pointer
bytes but does not prevent overwriting a return address with a ASCII
value. The open questions are the real stack frame layout of a shipping
`indiserver`, compiler stack-protector/NX settings, and whether the daemon
survives long enough for a hijack (the advisory only observed a crash).

Cheapest move up a rung: build affected `v2.2.4.2` with ASan and a disabled
stack canary, run `indiserver -p <loopback port> -v /bin/cat` in a private
loopback-only namespace, and send the exact one-packet PoC from issue #2472 to
127.0.0.1. First confirm the ASan frame at `lilxml.cpp:1281` in the real
binary; then vary tag lengths to map which saved return address is reached and
whether a chosen alphanumeric sequence lands there. All traffic stays on
127.0.0.1 addresses this plant starts.

## Unknowns and negatives

- No live `indiserver` build, no real TCP client, no port 7624 listener and no
  driver session were exercised here. The advisory's reachable path and
  one-packet claim remain reproduced only through the extracted parser call.
- The oracle's `isTokenChar` restricts tag bytes to ASCII alphanumerics and
  `_`; chosen-byte control is within that alphabet, not arbitrary binary.
- No pointer-sized target in a real object was controlled and no code
  execution was demonstrated. Stock stack layout on a shipping daemon is
  UNKNOWN. The advisory deliberately claims availability only.
- Other `sprintf` sites fixed in the same commit (bogus tag/attribute errors,
  local park-data/config files) are source-read only, not exercised locally.
- No exploit-framework claim was consulted; only CNA/OSV/VulnCheck records,
  the upstream issue and the fix commit were used.
