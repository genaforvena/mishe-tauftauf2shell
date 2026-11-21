# Provenance — rsyslog2shell frontier harness (2026-11-21)

All external reads were read-only provisioning from public sources. No probe
was sent off loopback; no rsyslog process, imhttp module, CivetWeb listener,
HTTP request or socket was created.

## Claim sources

- GitHub advisory GHSA-947w-69ph-mc2r, "Heap buffer overflow in imhttp plugin
  Basic Authentication handling / rsyslog", published 2026-06-23 by
  `rgerhards`, CVE-2026-55556, CWE-122, High, read 07:13Z:
  <https://github.com/rsyslog/rsyslog/security/advisories/GHSA-947w-69ph-mc2r>.
  Affected `>= 8.2110.0, < 8.2604.0`; patched `8.2604.0`; CVSS 4.0 8.2
  `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`.
  The advisory states "code execution has not been demonstrated" and requires
  imhttp built, installed, explicitly loaded and configured with Basic Auth;
  it knows of no distribution where imhttp is active by default.
- Bug-introducing commit `a8b8d6c1f969286adac3d465e6ac018968550667`
  ("imhttp updates - query parameter ingestion & basic auth support"), named
  by the advisory. Upstream fix commit
  `acde2ba25ea33816694b787859f4a727a247b6d6` ("imhttp: add route-scoped API
  key authentication") removes the dynamic Basic-Auth buffer entirely and
  adds `BASIC_AUTH_MAX_ENCODED`/`BASIC_AUTH_MAX_DECODED`; its patch is pinned.

## Exact pins and fetch method

Fetched with `curl -fsSL` from
`raw.githubusercontent.com/rsyslog/rsyslog/<ref>/contrib/imhttp/imhttp.c` and
from the GitHub commit `.patch` URL into `pins/`. `run.sh` verifies every
sha256 on each replay. Tag `v8.2603.0` does not exist (HTTP 404); `v8.2602.0`
is the last fetched tag inside the affected range.

| ref | file | sha256 |
| --- | --- | --- |
| tag `v8.2602.0` | `contrib/imhttp/imhttp.c` | `4e4a9d2c0ad5e55324fe922d768942d2973aca7298e813c8051f63dc7461ee25` |
| tag `v8.2604.0` | `contrib/imhttp/imhttp.c` | `48f69a6fa57c2d4bdd8f12ce83a647f35db9db968f4dce699bdb3ea4d0d9ba8c` |
| fix `acde2ba2…` | `.patch` | `f1935dd2dfeb76a6b115fdb64921b8674fc094fd803877b31b55e78ff26d9ff4` |

## Harness boundary

- `run.sh` asserts exact pinned lines (`v8.2602.0:62/71/72/687/699/701/702/
  703/705`, `v8.2604.0:68/69/79/774/786/792/793`) and extracts **verbatim**
  blocks under `#line contrib/imhttp/imhttp.c`: vulnerable struct 71-77 and
  function 687-720; fixed struct 78-83 and function 774-811.
- One clearly marked `/* INSTRUMENTATION — not upstream source */` block is
  injected between pinned lines 705 and 706 in the vulnerable build to read
  the chosen bytes immediately after the sink. No upstream line is changed or
  omitted.
- Collaborators: `struct mg_connection` + `mg_get_header()` return the
  synthetic in-memory `Authorization: Basic <b64>` header; `LogError` prints
  the fixed build's pinned diagnostic. `typedef int sbool;` is a harness stub
  for the upstream boolean type; the pinned fixed function only returns 0/1.
- `apr_base64_decode_len()` is the authentic function from the host's
  libaprutil-1 (`/usr/include/apr-1.0`, `libaprutil-1.so.0.6.3`). The sink
  `apr_base64_decode()` is redirected to `lab_base64_decode()`, an
  instrumented equivalent compiled into `driver.c` so ASan observes the write.
  Each run asserts `APR_EQUIV lab=N real=N bytes_match=1` against the real
  libaprutil decoder on the exact payload. The ASan summary frame is therefore
  the instrumented decoder; the caller frame is the pinned sink at
  `contrib/imhttp/imhttp.c:705`.
- The configured `IMHTTP_MAX_BUF_LEN` (8192) and `BASIC_AUTH_MAX_*` (2048/1536)
  values are pinned from the two source files, not guessed.
- `usable=` comes from glibc `malloc_usable_size()` on the zero-length
  allocation; it is a host observation, not an upstream guarantee.
- No pointer overwrite, saved return address value, control-flow diversion or
  marker execution was attempted. Advisory reachability, CVSS and severity
  remain claims. Rung 4 here is INSTRUMENTED (chosen bytes at chosen offsets
  past a zero-length heap allocation), not code execution.
- Trace hashes exclude ASan PID/address/path text so replays are byte-identical.
