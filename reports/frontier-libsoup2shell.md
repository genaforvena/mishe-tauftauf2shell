# frontier-libsoup2shell — data-URI base64 uninitialized-length heap over-read (CVE-2026-102555)

Status: **staged, rung 3 measured (W268 2026-11-26)**. The brief below was
written W266 from advisory text and the upstream patch; the operator's W268
intake pick built the cheapest experiment, and its observed result is
recorded in `lab/frontier/libsoup2shell/PROVENANCE.md` and at the end of this
brief. No wire path is claimed.

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

## Measured W268 result (author, not independent acceptance)

The fix parent `a4294044466df66ea98492d67bb74172ed3f8762` and fix
`e4f032268fa18f691a6c34d6adcb5b666f3e3f77` were fetched from public GitLab;
both pinned `soup-uri-utils.c` files are sha256-hashed by the runner. Full
meson build is blocked on this host (missing `libnghttp2`/`libpsl`, no root),
so the runner compiles the **verbatim** pinned source with lab-only shim
headers for generated files and a lab-only driver. No source line was edited.

`lab/frontier/libsoup2shell/run-all.sh` sha256
`4dadfa600b8f7b6b8b45faf8c867e159d09dd84752ee7a14a97f76c99ce9fd83`:
`RESULT PASS=19 FAIL=0 plain_rc=139`, rc 0, executed 12:45Z–12:46Z and
repeated three times with the same result. GCC and Clang ASan builds succeed.
GLib 2.80.0's `g_base64_decode_inplace()` fails the `input_length > 1`
precondition on the embedded NUL and leaves the caller's length untouched
(sentinel `4702111234474983745` survives a direct probe). The vulnerable
decoder therefore publishes a stale `GBytes` length: GCC ASan reports a
heap-buffer-overflow **READ of size 1**, `0 bytes after a 128-byte region`
allocated through `g_uri_unescape_bytes` at pinned `soup-uri-utils.c:405`.
A fresh process whose first URI is `data:;base64,%00%00%00` reproduces it;
an explicit 1024-byte groom then `data:;base64,A%00B` also reproduces it,
and the plain build rc 139. Fixed build is clean, reports size 0 for
`A%00B`, and decodes `aGVs%00bG8=` to the full `hello` (vulnerable: 3 bytes);
safe inputs are clean in both. Clang's stale values (7 and 4) stay inside
the 128-byte allocation, so Clang ASan is a preserved negative.

Grade: rung 3 real-source ASan OOB READ; rung 4 **NOT CLAIMED**. The consumer
is a lab-only byte-sum loop in the driver: no named adjacent object, no
chosen bytes at chosen offsets, no pointer control, no request-to-decoder
path, no command or r5. The CVE's `AV:N` remains advisory prose. A
request-to-decoder call path in a loopback consumer with an ASan report there
would change the assessment; so would a fixed-build counterexample.
