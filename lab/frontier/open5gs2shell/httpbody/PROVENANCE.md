# Real SBI HTTP body path — source-bound framing check (W2, 2026-11-25)

Question left open by W1: does a live SBI HTTP layer preserve the leading
CRLF(s) that the real `parse_multipart()` caller needs to derive an empty
boundary? This directory pins the real v2.8.0 server sources so the answer is
source-bound rather than inferred from the synthetic harness. It is **not** a
live NF replay and does not change the rung.

## Provisioning

Fetched 2026-11-25 with:

```
curl -fsSL -m 90 -o /tmp/open5gs-v2.8.0.tar.gz \
  https://codeload.github.com/open5gs/open5gs/tar.gz/refs/tags/v2.8.0
tar xzf /tmp/open5gs-v2.8.0.tar.gz -C /tmp/open5gs-v2.8.0 \
  --wildcards 'open5gs-2.8.0/lib/*'
```

Tarball SHA-256 `a04d66f66f6df62a376a2434a05a7268e08e4fc0cc1b9c56221467689a8b56ab`.
The tag is cross-checked: `lib/sbi/message.c` from the tarball hashes to
`a9678094c367e10c6ef4213b645ef23d55986616ad4ffd0af96e021687fcf64d`, exactly
the already pinned `provision/message-v2.8.0.c` in `pins.sha256`.

New pins (verified by `sh httpbody/run.sh`, SHA-256 in `../pins.sha256`):

- `provision/nghttp2-server-v2.8.0.c`
  `09093ac00b7506610e1c7471cda6d0ec76c18520507eec110722c306c4f76bfb`
- `provision/mhd-server-v2.8.0.c`
  `3c4bc060383fb453b4d0bd9018a842adc8fceb8a0be429adea2ca5e156da066f`

## Observed source behavior

Default nghttp2 backend, `on_data_chunk_recv()`
(`nghttp2-server-v2.8.0.c:1538-1611`): allocates/reallocs
`request->http.content`, then at `:1607`

```c
memcpy(request->http.content + offset, data, len);
request->http.content[request->http.content_length] = '\0';
```

`data` is the DATA-frame payload; there is no whitespace trim, skip or
canonicalization in this callback. On `NGHTTP2_FLAG_END_STREAM`
(`:1302-1323`) the same `request` is handed to `server->cb`.

Optional MHD backend, upload callback (`mhd-server-v2.8.0.c:639-681`), does the
same at `:677-678`: `memcpy(request->http.content + offset, upload_data,
*upload_data_size);` then NUL-terminates.

`ogs_sbi_parse_request()` (`message.c:933-1314`) passes `request->http`
directly to `parse_content()` (`:3111-3124`), which calls `parse_multipart()`
(`:3324`) when the content type is `multipart/related`; no body rewrite on
that path.

In `parse_multipart()` (`message.c:3356-3381`):

```c
preamble = 0;
if (http->content[0] == '\r' && http->content[1] == '\n')
    preamble = 2;
for (i = preamble; i < (http->content_length-preamble); i++) {
    if (http->content[i] == '\r' && http->content[i+1] == '\n')
        break;
}
boundary = ogs_strndup(http->content+preamble, i-preamble);
...
parsed = multipart_parser_execute(parser,
        http->content+preamble, http->content_length-preamble);
```

Exactly one leading CRLF is consumed as preamble. A wire body beginning
`\r\n\r\n` therefore yields an empty boundary at `:3372` and feeds the parser
the byte-identical remainder. The W1 staged 394-byte harness body is that
remainder; the real wire body is 396 bytes with one extra leading CRLF. The
`realcaller/` harness already exercises this exact chain: attack mode
(`BODY_LEN=396`) prints `BOUNDARY_LEN=0`, faults ASan at the pinned `:260`
sink and writes the periodic bytes into the plain-build canary; staged mode
(394 bytes) derives `BOUNDARY_LEN=2 BOUNDARY=a:` and stays clean.

## Limits

No Open5GS process was built or driven on loopback. Both HTTP layers were read
from the pinned v2.8.0 tag, not executed; the parse chain was exercised only
through the existing synthetic `realcaller/` harness with the real boundary
extraction and verbatim pinned parser. The finding resolves the framing
question at source level. It does not establish a live-process rung 4 or any
rung 5 behavior. Full-NF provisioning remains bounded out this wake: dev
packages for mongoc, nghttp2, talloc and c-ares are not installed and the
session is uid 1000, so a local-prefix dependency build plus full NF
configuration would be required (not attempted).
