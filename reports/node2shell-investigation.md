# Node2Shell investigation — CVE-2026-123828

One-byte heap overflow in Node.js HTTP/2 `session.altsvc()` handling
(`src/node_http2.cc`). Target admitted 2026-11-20 (operator, standing
approval #6, similar-things mandate). This report records every rung as
observed; unknowns stay unknown.

## Ground truth (verified 2026-11-20, first wake of node2shell)

All claims below were re-derived from primary sources, not taken from
Snyk or prior walls:

- **Fix commit** `nodejs/node@ae9ab37d62` — "http2: avoid overflowing
  ALTSVC buffers" (Matteo Collina, GPG-verified; PR nodejs-private#1035;
  CVE-ID in message). The diff removes `String::WriteFlags::kNullTerminate`
  from both `WriteOneByteV2` calls in `Http2Session::AltSvc`
  (`src/node_http2.cc`), because `nghttp2_submit_altsvc()` consumes
  explicit lengths. Upstream's own regression test uses a 1048-char
  origin and a 1050-char alt value.
- **Allocation** (`src/util.h` / `src/util-inl.h`): `MaybeStackBuffer<T>`
  default stack storage is 1024 items; `AllocateSufficientStorage(len)`
  `Realloc`s exactly `len` bytes — no `+1`. Heap path requires
  `len > 1024`.
- **Termination write**: 24.x/26.x pass `kNullTerminate` explicitly;
  ≤22.x call V1 `WriteOneByte(isolate, *origin)` whose V8 default
  (`length == -1`, `NO_OPTIONS`) writes `buffer[write_length] = '\0'`
  (V8 `WriteHelper`, present unchanged in v22.23.5's vendored V8).
- **Tagged-source differential** (fetched and diffed): `v24.22.2` and
  `v26.13.0` carry the vulnerable code; `v24.22.3` and `v26.13.1`
  carry the fix verbatim.
- **Official advisory** (nodejs.org November 2026 security releases):
  remote unauthenticated heap-buffer-overflow "with a long origin",
  app passes "attacker-controlled value such as a request's :authority"
  to `Http2Session.altsvc()`; affects active release lines 24.x, 26.x;
  reported by zonduu.

### 22.x discrepancy (resolved)

Snyk claims 22.x < 22.23.5 fixed in 22.23.5. Tagged sources contradict
the "fixed" half: `v22.23.4` and `v22.23.5` `node_http2.cc` are
byte-identical in the AltSvc function (old V1 call, no backport), and
v22.23.5's vendored V8 still null-terminates. So 22.x through 22.23.5
still carries the same OOB write **as a rung-0 source-read claim**
(not reproduced on a 22.x build yet; the official advisory does not
list 22.x). Host stock `v20.20.2` (EOL line) has the identical V1
pattern — read from the `v20.20.2` tag.

## Trigger shape

```
origin = 'https://' + request[':authority']      // app-forward pattern
stream.session.altsvc(alt, origin)               // id=0, origin non-empty
```

- Heap-backed when `origin_len > 1024`; C++ CHECK caps
  `origin_len + value_len <= 16382`. Attacker controls the exact
  allocation size (1025..~16370) via authority length
  (`origin_len = 8 + authority_len`) and the pre-overflow content.
- The value buffer overflows too if the app's alt string exceeds 1024 —
  realistic only when the attacker controls the alt value; primary
  remote vector is the origin buffer.
- **glibc placement class**: `origin_len ≡ 8 (mod 16)` ⇒
  `request2size = origin_len + 8` ⇒ `malloc_usable_size == origin_len` ⇒
  the NUL lands exactly on the **size-field LSB of the following chunk**
  (poison-NUL-byte primitive, same class as Ruby2Shell). Other residues
  land in intra-chunk slack or the next chunk's unused `prev_size` —
  no immediate effect.

## Evidence ladder

- **Rung 0** — suspected: advisory + fix-diff read as specification
  (above).
- **Rung 2/3-class observation on stock glibc (not deterministic)** —
  first wake, 2026-11-20: stock prebuilt `node v20.20.2` (official
  binary, production glibc of this host), loopback-only, single
  unauthenticated request with `authority_len = 1040`
  (`origin_len = 1048 ≡ 8 mod 16`): server died `SIGABRT (rc=134)` with

  ```
  malloc(): mismatching next->prev_size (unsorted)
  ```

  glibc's own heap-integrity detector fired — the OOB NUL had cleared
  the size LSB of a free unsorted chunk. Observed **1/6** identical
  runs; a following 45-run sweep over `origin_len` 1024..1112 produced
  no further aborts (natural rate ≈2%, layout-dependent). Real
  corruption observed on a stock build, but not a reproducible-crystal
  rung-2 result until determinism is groomed. Version honesty: v20.20.2
  is an EOL line carrying the same code; the officially listed affected
  lines are 24.x/26.x, which get the ASan differential below.
- **Rung 1/2 deterministic detector — in flight**: ASan build of
  affected `v24.22.2` (clang 18.1.3, `./configure --enable-asan
  --without-intl --without-npm --without-corepack`, `make -j2`),
  detached (spans wakes on this 2-core host). Then: same harness →
  expected deterministic `heap-buffer-overflow WRITE of size 1`;
  then apply the fix diff to the tree, incremental rebuild → fixed
  control `v24.22.3`-equivalent, same harness, no report.

## Reproduction (stock-glibc abort observation)

```
# terminal 1
node lab/repro/node2shell-rung1-server.js 0
# terminal 2 (port from server's LISTEN line; repeat runs for the ~2% class)
node lab/repro/node2shell-rung1-client.js <port> 1040
```

Harness: `lab/repro/node2shell-rung1-server.js` (HTTP/2 server on
127.0.0.1 forwarding `:authority` into `session.altsvc` — the advisory's
app precondition) and `lab/repro/node2shell-rung1-client.js`
(single request, syntactically valid long authority, waits for the
ALTSVC frame echo proving the full path executed).

## Lab provenance (this wake)

- Provisioning: nodejs.org dist tarball `node-v24.22.2.tar.gz` (117 MB);
  `apt-get install clang` → clang 18.1.3 (08:46Z); tagged-source
  fetches of `node_http2.cc`/`util.h`/`util-inl.h`/V8 `api.cc` from
  raw.githubusercontent (provisioning, no probing).
- ASan build script: `lab/build/node2shell-build-asan.sh` (lab/build is
  gitignored bulk; the exact commands are reproduced above so a reader
  can rebuild from a clean checkout plus the official tarball).
