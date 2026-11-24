# Real c-icap build — W1 (2026-11-24 18:3xZ)

Provisioning only: both tarballs came from codeload GitHub tags; no probe or
traffic off loopback. Exact source hashes verified against the pinned harness
copies: the four `C_ICAP_0.6.5` files in `../pinned/` match the release
tarball byte-for-byte (sha256 `b4988efe…37ad`, `fa3fe4ef…b39219a`,
`e953e2f6…1e4619`, `760e573b…4e13fb3`). Release tarball sha256
`6ac51b6dd39690a6ccc62e807f065e92131498687d4201a69ae9570b68bab1e5`.

```
curl -sSL -o C_ICAP_0.6.5.tar.gz \
  https://codeload.github.com/c-icap/c-icap-server/tar.gz/refs/tags/C_ICAP_0.6.5
tar xzf C_ICAP_0.6.5.tar.gz
cd c-icap-server-C_ICAP_0.6.5 && autoreconf -i
mkdir ../build-asan && cd ../build-asan
CFLAGS='-O0 -g -fsanitize=address -fno-omit-frame-pointer' \
LDFLAGS='-fsanitize=address' ../c-icap-server-C_ICAP_0.6.5/configure
make -j4
gcc -std=gnu11 -O0 -g -fsanitize=address -fno-omit-frame-pointer \
  -I ../c-icap-server-C_ICAP_0.6.5/include -I include \
  real_api_harness.c -o real_api_harness \
  -L .libs -licapapi -Wl,-rpath,$PWD/.libs
./real_api_harness attack 90
./real_api_harness safe x
```

Fixed control: GitHub has **no `C_ICAP_0.6.6` tag** (latest tag is 0.6.5).
Apply `../pinned/fix.patch` (`05dcead`) to a copy of the 0.6.5 tree; hunk 2
(teardown loop) fails to apply verbatim because of surrounding drift, so apply
its exact change (`i < 5` bound, NULL-out) by hand, then rebuild with the same
flags. No released 0.6.6 binary was built; this is a patch-derived control.

Observed (raw outputs in `../evidence/real-*.out`, gitignored):

- vuln ASan, sixth value `90`, `72`, `4242`: each prints
  `parse=0 entities5=<addr> trash0=<same addr> alias=1 trash0_type=2
  trash0_start=<value>`, then ASan `heap-use-after-free`, `READ of size 4`,
  `destroy_encaps_entity header.c:631` from `ci_request_destroy
  request_common.c:417`, freed at `header.c:635` from `:413`, allocated at
  `header.c:616` from `ci_request_alloc_entity request_common.c:200`; rc 1.
- vuln ASan, four-entity safe: `entities5=(nil) trash0=(nil) alias=0`,
  `destroy done`, rc 0, no sanitizer report.
- upstream-patched fixed ASan, attack `90` and safe: `entities5=(nil)`,
  `alias=0`, `destroy done`, rc 0, no sanitizer report.

Scope limit: the header string is passed directly to the exported
`process_encapsulated()` on a real `ci_request_t`; this is NOT a socket, not
`parse_header()`/`process_request()`, and not a running `icap-server`. No
pointer/IP/command control and no r5.
