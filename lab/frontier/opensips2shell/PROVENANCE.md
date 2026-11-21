# Provenance — opensips2shell frontier harness (2026-11-21)

All fetching was read-only provisioning from public sources; no probe was sent
off loopback and no OpenSIPS process was built or run.

## Claim sources

- GHSA-5gm5-wj62-p234, "xmpp: unauthenticated stack overflow in ENC_SIP_URI
  via unbounded sprintf", published 2026-09-28 by razvancrainea, read 05:59Z:
  <https://github.com/OpenSIPS/opensips/security/advisories/GHSA-5gm5-wj62-p234>.
  Severity High 8.6, CVSS v3 `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H`.
  Affected `>=4.0.0,<4.0.2` and `>=3.6.0,<3.6.9`; patched `4.0.2` and
  `3.6.9`. No CVE ID was visible on the advisory page or in a targeted search
  at fetch time — treated as UNKNOWN, not asserted. The advisory itself
  reports RCE as *possible* depending on stack canary/ASLR/NX, and a reliable
  unauthenticated crash of the XMPP receiver process as the practical impact.
  The server-mode route needs `modparam("xmpp","backend","server")`; the
  default component backend reaches the same sink from the configured Jabber
  server, not a raw listener.
- Upstream fix commit `ec24165bc25fa462e08cdb33ee8071f58e166d36`, "xmpp:
  prevent unauthenticated message URI overflow", read 05:59Z:
  <https://github.com/OpenSIPS/opensips/commit/ec24165bc25f.patch>. Its body
  says `Fixes GHSA-5gm5-wj62-p234`. It replaces the unbounded macro with
  `xmpp_encode_sip_uri()` (bounded `snprintf`, length guard), grows
  `buf_from` to `MAX_URI_SIZE + 1`, rejects over-long JIDs, and requires
  dialback authentication before processing inbound `<message/>` stanzas.
- No public exploit was needed or used; the advisory's own reproduction and
  the pinned source were enough to build the local replay.

## Exact pins and fetch method

Fetched with `curl -fsSL` from
`raw.githubusercontent.com/OpenSIPS/opensips/<tag>/modules/xmpp/<file>` and
`.../<tag>/config.h` into `lab/frontier/opensips2shell/pins/`; `run.sh`
verifies these sha256 values on every replay.

| ref | file | sha256 |
| --- | --- | --- |
| tag `4.0.1` (tag object `23d8d98e…`, commit `1747e6ed…`) | `xmpp.h` | `1533677b92768ea13efc324a452ca4e2c7b8b0ef475f228588d6179ce55481bc` |
| tag `4.0.1` | `xmpp.c` | `1f9bef407bff401142243dfd1a628322e25c0382a26439a755249b6020d628e0` |
| tag `4.0.1` | `xmpp_server.c` | `750abf2fc553bc6a2defc492b2db93ea0603566f5392ab20e18c6597905b68c5` |
| tag `4.0.2` (tag object `0cccb6ef…`, commit `ff6840d5…`) | `xmpp.h` | `10c856117666dfd3fe4f1f16a8bfac984b58092a50d6690ae3d803c1a3d8c25f` |
| tag `4.0.2` | `xmpp.c` | `ce3d681a73991318a17b806d7450f17f49c1f8e99163e7965fdbc4c372d32972` |
| tag `4.0.2` | `xmpp_server.c` | `d9fe0f6b8737ea1d69c8146ec1c374bcef5d537c5cbb43115587fcb10797e38a` |
| tag `4.0.2` | `config.h` | `90206e1f7c24e4ec5e5a682bba3f570c70581896c9e5e979019a9fec6fd62efa` |

`config.h:76` pins `MAX_URI_SIZE 1024`. The vulnerable pins are byte-identical
to the advisory's quoted macro and call site; no source edit was made.

## Harness boundary

`run.sh` extracts VERBATIM `modules/xmpp/xmpp.h:73-82` and
`modules/xmpp/xmpp.c:280-285` at tag `4.0.1`, and
`modules/xmpp/xmpp.h:46-71` plus `modules/xmpp/xmpp.c:281-303` at tag `4.0.2`,
under `#line` directives. It also asserts exact pinned lines in
`xmpp_server.c` for the unauthenticated stanza path (vulnerable line 361/382)
and the fixed dialback gate (fixed line 374). `driver.c` supplies stub
`str`, `LM_ERR`, `CRLF`, an attacker-chosen `from` string, and instrumentation
after the pinned statements. The non-ASan vulnerable build omits the pinned
`Contact:` `snprintf` (lines 287-289) so the chosen bytes past `buf_from`
remain observable in this test frame; that omission is a measurement choice,
not a claim about the shipping function. ASan mode uses the same verbatim
sink and reports the write at the pinned call site.

No OpenSIPS daemon, socket, XMPP stream, XML parser, dialback state, VM or
network is used. No control-flow diversion, pointer overwrite or marker
execution is claimed: the bytes past the array are observed in a synthetic
local frame, and the shipping stack layout, canary, ASLR and NX were not
exercised.
