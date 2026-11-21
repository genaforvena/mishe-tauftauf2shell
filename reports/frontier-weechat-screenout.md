# Frontier brief — WeeChat relay hdata OOB write (SCREENED OUT)

**Decision (2026-11-21 12:40Z): SCREEN OUT of the X2Shell chosen-byte lane.**
The bug is real and fix-backed, but the overrunning bytes are compiled-in
hdata names, not attacker-chosen bytes, and the relay path needs an
authenticated client. No harness and no window.

## Claim sources

- GHSA-8wr2-x42m-7fxv / WSA-2026-22, published 2026-10-31 by flashcode;
  <https://github.com/weechat/weechat/security/advisories/GHSA-8wr2-x42m-7fxv>,
  <https://weechat.org/doc/weechat/security/WSA-2026-22>. Scout-reported:
  Moderate CVSS 5.5 `AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H`, CWE-122/131,
  affected 0.3.7–4.10.1, fixed 4.10.2, no CVE assigned.
- Fix commit `9fb7f87379d5a6aa275e25a0a48546a5a819495b`, patch
  <https://github.com/weechat/weechat/commit/9fb7f87379d5a6aa275e25a0a48546a5a819495b.patch>.

## Source-bound mechanism and screen-out reason

Raw `v4.10.1/src/plugins/relay/weechat/relay-weechat-msg.c` (fetched and read
this wake) has `relay_weechat_msg_add_hdata` at `:583`,
`path_returned = malloc(strlen(path) * 2)` at `:662`, `strcpy` at `:666` and
`strcat(path_returned, hdata_name)` at `:678-679`. The scout's rendered reader
reported these 1–3 lines earlier; raw bytes are authoritative. A repeated
`/next_nick` segment is replaced by the much longer registered hdata name
(`/irc_channel_speaking`, scout-reported from `irc-channel.c:1745-1746`), so
the allocation based on the request length is too small and `strcat` writes
past it. The fix replaces the malloc/strcpy/strcat chain with dynamic strings.

The overflow length and repetition count are attacker-controlled, but the
written bytes come from fixed, compiled-in hdata names. That is not the
attacker-chosen-byte primitive this lab drives toward rung 4. The relay
`hdata` command is also gated on `RELAY_WEECHAT_AUTH_OK` (scout-reported from
`relay-weechat-protocol.c:1838-1840`), so the claimed path is authenticated.
No bytes were reproduced locally; no claim of exploitation is made.
