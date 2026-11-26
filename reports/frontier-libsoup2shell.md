# frontier-libsoup2shell — data-URI base64 uninitialized-length heap over-read (CVE-2026-102555)

Status: **candidate brief only, no local lab yet**. Written 2026-11-26 W266
from primary advisory text and the upstream patch; nothing here is an
observed local result. Next wake decides whether to build it.

## Claim source and scope

- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-102555 (Red Hat CNA,
  published 2026-09-29, updated 2026-11-23): `soup_uri_decode_data_uri()`
  treats percent-decoded base64 data-URI payloads as NUL-terminated when
  calling `g_base64_decode_inplace()`; with embedded NUL the decoded length
  can stay uninitialized and be used as the `GBytes` size, giving an OOB read
  or crash. CWE-125, CVSS3 8.2 `AV:N/AC:L/PR:N/UI:N/C:L/I:N/A:H`. Credit:
  Hongduo Zhao. Red Hat fixed builds are listed for RHEL 10 / 10.0 EUS.
- Upstream fix: GNOME GitLab commit
  `e4f032268fa18f691a6c34d6adcb5b666f3e3f77` (parent per GitLab API
  `a4294044466df66ea98492d67bb74172ed3f8762`, Patrick Griffis, 2026-09-04),
  "uri-utils: Don't treat base64 data URI content as a NUL-terminated string",
  fixes GNOME issue #554. Patch:
  https://gitlab.gnome.org/GNOME/libsoup/-/commit/e4f032268fa18f691a6c34d6adcb5b666f3e3f77.patch .
  Upstream NEWS puts it in 3.7.3; Debian tracker 3.8.0-1.
- libsoup is the GNOME HTTP client/server C library, so the input is a URL or
  web content parsed by a request-handling process, unlike the local-only
  SQLite candidate. That makes it the best *wire-adjacent* candidate found in
  this sweep. No live consumer path is claimed until built locally.
- Checked before staging: no report, charter, manifest row or lab lane for
  libsoup; not on the wall's do-not-duplicate or screened-out lists.

## Source-bound mechanism

The fix patch shows both sides of the bug. Vulnerable
`libsoup/soup-uri-utils.c` around `:408-420`:

```c
GByteArray *unescaped_array = g_bytes_unref_to_array (bytes);
gsize content_length;
g_base64_decode_inplace ((gchar*)unescaped_array->data, &content_length);
unescaped_array->len = content_length;
bytes = g_byte_array_free_to_bytes (unescaped_array);
```

`g_base64_decode_inplace()` measures with `strlen()`; `A%00B` percent-decodes
to `A\0B`, so its input length is 1, which fails the function's preconditions
and returns without setting `content_length`. The uninitialized `gsize`
becomes `GByteArray.len`, hence the `GBytes` size. The fix uses
`g_base64_decode_step()` with the real byte count (safe in place because
base64 output never exceeds input) and adds regression vectors including
`data:;base64,%00%00%00` and `data:;base64,aGVs%00bG8=`.

## Honest feasibility

Potential grade: rung 3 ASan-confirmed OOB READ at most, rung 4 PARTIAL only
if a named consumer or request path is demonstrated. Primitive is a read with
an uncontrolled length, not a write, pointer control or command. The CVE's
`AV:N` is advisory prose; no wire request is claimed here. A successful
`g_base64_decode_step()` fixed build must be clean on the same inputs.

## Cheapest rung-moving experiment

Pin the fix parent and fix commits, build libsoup with ASan against a
lab-only GLib, call `soup_uri_decode_data_uri()` on the patch's two new
vectors plus a direct `data:;base64,A%00B`, and use
`g_bytes_get_data()/g_bytes_get_size()` in a driver to observe the over-read.
If that works, drive the same URI through a loopback `libsoup` server handler
and name the consumer that calls the decoder. Would change the assessment:
an ASan READ report with the real sink, a fixed-build counterexample, or a
demonstrated request-to-decoder call path.
