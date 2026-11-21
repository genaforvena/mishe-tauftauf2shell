# frontier-opensips2shell — OpenSIPS XMPP `ENC_SIP_URI()` unbounded `sprintf` stack overflow

## Claim (not yet observation)

GHSA-5gm5-wj62-p234, "xmpp: unauthenticated stack overflow in ENC_SIP_URI via
unbounded sprintf", published 2026-09-28 by razvancrainea. Severity High 8.6,
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H`. Affected versions
`>=4.0.0,<4.0.2` and `>=3.6.0,<3.6.9`; patched `4.0.2` and `3.6.9`. No CVE ID
was visible on the advisory or in a targeted search at fetch time (UNKNOWN,
not asserted). The claim: an XMPP JID `from` attribute is copied by
`sprintf(buf, "sip:%s", src)` into a 256-byte stack array with no length
check; the XML parser permits attribute lengths up to `XODE_STREAM_MAXNODE`
(1000000). One unauthenticated stanza on the XMPP server-mode TCP listener
(default 5269) is enough. Server mode is configured with
`modparam("xmpp","backend","server")`; the default component backend reaches
the same sink from the configured Jabber server, not a raw listen port. The
advisor reports a reliable crash of the single XMPP receiver process and
RCE as *possible* depending on canary/ASLR/NX. Treat all of this as claim
until reproduced.

Sources: <https://github.com/OpenSIPS/opensips/security/advisories/GHSA-5gm5-wj62-p234>,
<https://github.com/OpenSIPS/opensips/commit/ec24165bc25fa462e08cdb33ee8071f58e166d36.patch>.

## Source-bound mechanism

Affected pin: tag `4.0.1`, `modules/xmpp/xmpp.h:73-82`:

```c
#define ENC_SIP_URI(dst, buf, src) \
    do{\
        char* slash = strchr(src, '/'); \
        if(slash)\
            dst.len = slash - src + 4;\
        else\
            dst.len = strlen(src) + 4; \
        dst.s = buf;\
        sprintf(buf, "sip:%s", src);\
    }while(0)
```

The `dst.len` assignment is bookkeeping only; it never bounds the `sprintf`.
Call site in pinned `modules/xmpp/xmpp.c:278-285`:

```c
int xmpp_send_sip_msg(char *from, char *to, char *msg)
{
  str msg_type = { "MESSAGE", 7 };
  str hdr, fromstr, tostr, msgstr;
  char buf[512];
  char buf_from[256];

  ENC_SIP_URI(fromstr, buf_from, from);
```

A 299-byte `from` produces `4 + 299 + 1 = 304` bytes into `buf_from[256]`:
48 bytes past the end, with the attacker choosing both length and every
overflow byte after the fixed `sip:` prefix. A `from` containing `/` also makes
the stored length smaller than the true written length (the macro counts only
up to the slash, while `sprintf` copies the whole JID). The pinned
`modules/xmpp/xmpp_server.c:361-382` reaches this sink for `<message/>`
without a dialback state check; `xmpp_server_child_process()` accepts any TCP
client.

Upstream fix commit `ec24165bc25fa462e08cdb33ee8071f58e166d36` (authored
2026-09-04, committed 2026-09-07, body `Fixes GHSA-5gm5-wj62-p234`) replaces
the macro with `xmpp_encode_sip_uri()` (`snprintf` into a caller-supplied size,
fail closed when `full_len > MAX_URI_SIZE - 4`), grows `buf_from` to
`MAX_URI_SIZE + 1` (1025 per pinned `config.h:76`), rejects over-long `from`/
`to` in `xmpp_send_sip_msg()`, and ignores `<message/>` until
`conn->authenticated` is set (pinned fixed `xmpp_server.c:374`).

## Pins and local harness

Exact sha256 values, tag objects and fetch URLs are in
`lab/frontier/opensips2shell/PROVENANCE.md`; all seven pinned files live under
`lab/frontier/opensips2shell/pins/` and are re-verified by `run.sh` on every
replay. `run.sh` extracts verbatim pinned `xmpp.h:73-82` and `xmpp.c:280-285`
(tag 4.0.1) plus `xmpp.h:46-71` and `xmpp.c:281-303` (tag 4.0.2) under `#line`
directives; it also asserts the exact pinned server-mode lines and
`MAX_URI_SIZE`. `driver.c` supplies stub collaborators and an attacker-chosen
`from` string; no daemon, socket, XMPP stream, XML parser or network is used.
The non-ASan vulnerable build omits the pinned `Contact:` `snprintf`
(xmpp.c:287-289) so the chosen bytes past `buf_from` remain observable in the
test frame; this is a measurement choice, not a claim about the shipping stack
layout.

## Evidence ladder (observed 2026-11-21 06:02Z)

Working-tree replay of `bash lab/frontier/opensips2shell/run.sh <outdir>`:
**26 PASS / 0 FAIL, `ALL CHECKS PASSED rc 0`**, trace
`sha256=a69657bb243b83b850b332a4307996f5705d6b0bd6b3cdefbccba022c0c78b06`
(canonical lines only; ASan PID/address/path text excluded). Two clean
`git archive HEAD` replays at commit `b4bc31a`, run into separate absolute
output directories from extracted trees, each gave 26 PASS / `ALL CHECKS
PASSED rc 0` with the same trace sha256 — byte-identical between directories
and with the working-tree run.

- **Rung 1 (reproducible trigger)** — `LAYOUT build=vuln mode=chosen
  buflen=256 fromlen=299 written=303 overflow=48 stored_len=303`: the verbatim
  macro writes 304 bytes including NUL into a 256-byte stack array.
- **Rung 2 (observed state/accounting failure)** — with `/` at offset 10 of
  the JID, `LAYOUT ... written=303 overflow=48 stored_len=14`: stored length
  and actual write diverge by 289 bytes while the overflow still happens.
- **Rung 3 (ASan-confirmed corruption)** — `ERROR: AddressSanitizer:
  stack-buffer-overflow`, `WRITE of size 304`, frame `xmpp.c:285` from the
  verbatim pinned call site; the reported frame has a 256-byte `buf_from`
  followed by a redzone.
- **Rung 4 (INSTRUMENTED only)** — the 16 bytes at `buf_from + 256` in the
  no-canary test frame are byte-identical to the attacker pattern beginning
  at `from[252]`: `CHOSEN observed=535455565758595a4142434445464748`,
  `CHOSEN expected=535455565758595a4142434445464748`, `CHOSEN_MATCH=1`.
  This is chosen-byte control in the lab frame, not demonstrated execution:
  no return address, pointer or marker was touched, and the shipping stack
  layout, canary, ASLR and NX were not exercised. The fixed control writes
  1024 bytes into a 1025-byte buffer (`overflow=0`) and rejects a 1500-byte
  JID (`rejected=1`).

## Feasibility and cheapest next experiment

Ranking: **HIGH tractability relative to this plant's other finds**. Unlike
the held dnsmasq candidate, this one has pinned affected *and* patched release
tags, a readable upstream fix commit, a PR:N network vector, and fully
attacker-chosen overflow bytes (length and contents). The residual gates are
the documented `backend=server` configuration and build mitigations
(canary/ASLR/NX) that decide whether the stack smash reaches control flow.

Cheapest experiment that would move it up a rung: in `lab/`, build stock
OpenSIPS `4.0.1` with the `xmpp` module under ASan (and a second no-canary
build), bind only 127.0.0.1 with `backend=server`, send one stream header plus
one `<message from="…299 chosen bytes…" to="victim@sip.domain">` stanza on the
loopback XMPP port, and record the real receiver's ASan report, crash and
post-overflow stack bytes. If the chosen bytes reach a saved return address
or a function pointer in that real frame, attempt a benign marker (never an
external action) before claiming rung 4; otherwise keep the instrumented
label. Repeat with tag `4.0.2` as the control. Do not contact external XMPP
servers or any host other than 127.0.0.1.

## Disposition

Frontier brief plus local harness only. No full-daemon build this wake, no
admission requested by frontier; the operator owns admission. Severity,
RCE possibility and configuration details remain advisory claims except where
the verbatim pinned source and the local ASan observation speak.

## Handoff

Both required artifacts for a find are live: this brief and a registered
two-pane `opensips2shell` window on the inner tmux socket (window index 34,
both panes capture-verified 2026-11-21T06:05:46Z: top tails this brief, bottom
runs `plant_view --role opensips2shell --output --log --follow`). The registry
has 36 JSON-valid windows and the seed wall is
`.mishe-tauftauf/walls/opensips2shell.md`. Witness replay request DM #605 and
operator handoff DM #606 were sent at 06:08Z; the handoff states the window
already exists. No charter, route entry or wake unit is claimed by frontier;
the operator owns admission.
