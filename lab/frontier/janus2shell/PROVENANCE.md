# Provenance — janus2shell frontier harness (2026-11-21)

All external reads were read-only provisioning from public sources. No probe
was sent off loopback; no Janus process, HTTP request, WebRTC session or
recording file on a live system was created.

## Claim sources

- GitHub security advisory GHSA-8qwr-6p52-4vj9, "Record&Play: a recording with
  an over-long codec string (a=fmtp) overflows a 1500-byte buffer and
  crash-loops Janus", published 2026-10-12, read 06:55Z:
  <https://github.com/meetecho/janus-gateway/security/advisories/GHSA-8qwr-6p52-4vj9>.
  Affected `<=1.4.2`, `<=0.16.2`; fixed `1.4.3`, `0.16.3`; CVSS 3.1 7.5
  `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`; "No known CVE"; maintainer lminiero;
  reporter AdamKorcz (Anthropic / Ada Logics). Includes a Docker+Python
  reproducer that this harness does **not** run.
- Upstream fix commit `e55e2915a2801f18495c7f0d049af9274dd70065` (1.4.x) and
  its 0.16.x backport `c31cad9768368b996aa68753df1656fe4f30af7e`:
  <https://github.com/meetecho/janus-gateway/commit/e55e2915a2801f18495c7f0d049af9274dd70065.patch>.
  Each adds only the `len >= sizeof(prebuffer)` guard at two sites.
- v1.4.3 `CHANGELOG.md` and NVD 2.0 keyword query corroborate the release
  and the absent CVE, respectively.

## Exact pins and fetch method

Fetched with `curl -fsSL` from `raw.githubusercontent.com/meetecho/janus-gateway/<ref>/<path>`
into `pins/` and from the GitHub commit `.patch` URL. `run.sh` verifies every
sha256 on each replay.

| ref | file | sha256 |
| --- | --- | --- |
| tag `v1.4.2` | `src/plugins/janus_recordplay.c` | `c06e9396b593f384b3ab9b65a3a4ec3be9dada397c1bec86d8c5b01db55c4a98` |
| tag `v1.4.3` | `src/plugins/janus_recordplay.c` | `745c414595c874d961a220c3d194769a2172c9e57fbe809d9ee3dd2dca7bad6e` |
| tag `v0.16.2` | `plugins/janus_recordplay.c` | `badbecd6dfc03d5a6e627c3882415045a4b1cfa585f8f3915a9ec42f39362827` |
| tag `v0.16.3` | `plugins/janus_recordplay.c` | `892746e3f6c608cd5c47935c3dacdc7fc21a745a165abff4ff4bebdf6187222a` |
| fix `e55e2915…` | `.patch` | `bc7e951fef14dfd1d98b099f253c1549aa211d855bbed710d02108569d26ae62` |

## Harness boundary

- `run.sh` asserts exact pinned lines (v1.4.2 `:664/:670/:701/:703/:707/:714`,
  v1.4.3 `:707/:708/:712/:719`, legacy `:712`/`:705`) and extracts **verbatim**
  blocks under `#line src/plugins/janus_recordplay.c`:
  vulnerable 669-670 + 701-714; fixed 669-670 + 701-719.
- A single clearly marked `/* INSTRUMENTATION — not upstream source */` block
  is injected between pinned lines 707 and 708 in the vulnerable build to
  observe chosen bytes immediately after the `fread`; the non-ASan run can
  fault at function return because the write reaches saved frame state, so
  the observation is printed and flushed before that point. No upstream line
  is changed or omitted.
- Stubs: `JANUS_LOG` (records rejection, prints the pinned diagnostic),
  `g_strerror`, `gboolean`, and `mjr[]` as the `.mjr` byte stream opened with
  `fmemopen`. `len` is read by the pinned code from the synthetic 16-bit
  big-endian header field; the harness never supplies it directly.
- `requested=` in the trace comes from a global snapshot taken before the
  pinned block (the local `len` is itself overwritten by the write in the lab
  frame, which is reported as `ADJACENT_LOCAL_OVERWRITTEN=1`).
- The vulnerable non-ASan and protected builds use `-fno-stack-protector` and
  the host default respectively: the former lets chosen bytes be observed,
  the latter is a control that aborts on canary corruption. Shipping compile
  flags are **UNKNOWN**; neither observation is a claim about a stock build.
- No pointer overwrite, saved return address value, control-flow diversion or
  marker execution was attempted. Advisory reachability and severity remain
  claims. The advisory's availability-only rating is preserved; rung 4 here
  is INSTRUMENTED (chosen bytes and adjacent local in a synthetic frame).
- Trace hashes exclude ASan PID/address/path text so replays are byte-identical.
