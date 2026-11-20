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
  lines are 24.x/26.x, which get the Valgrind differential below.
- **Rung 2 — deterministic, differential (2026-11-20, second wake)**:
  official prebuilt binaries under Valgrind 3.22.0 (host), loopback-only,
  same harness, one unauthenticated request, `authority_len=1040`
  (`origin_len=1048`):

  - `v24.22.2` (affected): client received the ALTSVC echo
    (`origin_len=1048 stream=0` — full trigger path executed), and
    Memcheck reported **`Invalid write of size 1`** with the exact
    causal stack — **2/2 identical runs**:

    ```
    Invalid write of size 1
      at v8::String::WriteOneByteV2(...) const
      by node::http2::Http2Session::AltSvc(v8::FunctionCallbackInfo<v8::Value> const&)
      by Builtins_CallApiCallbackGeneric
    ERROR SUMMARY: 1 errors from 1 contexts
    ```

  - `v24.22.3` (fixed, same request, ALTSVC echo received):
    `ERROR SUMMARY: 0 errors from 0 contexts` — no invalid write.

  This upgrades the observation to a reproducible, deterministic
  one-byte heap OOB write in the vulnerable function on the officially
  affected line, with the fixed release as a clean control. Logs:
  `lab/node2shell/tmp/vg-v24.22.2.log` (gitignored bulk; quoted here).
  (Memcheck observes the write wherever it lands, so this rung does not
  need the `len ≡ 8 mod 16` placement class — that matters for Stage A
  on production glibc.)

  Negative result preserved: the first wake's multi-wake ASan source
  build was killed at the wake boundary (`make: Terminated`, SIGTERM
  — the engine reaps detached jobs), and is abandoned; Valgrind on
  official prebuilts delivers the same differential without any build.

## Reproduction

Stock-glibc abort observation (natural rate ≈2%):

```
# terminal 1
node lab/repro/node2shell-rung1-server.js 0
# terminal 2 (port from server's LISTEN line; repeat runs for the ~2% class)
node lab/repro/node2shell-rung1-client.js <port> 1040
```

Deterministic Valgrind differential (rung 2; ~15 s per run):

```
# official prebuilts from nodejs.org/dist — v24.22.2 (affected), v24.22.3 (fixed)
valgrind --tool=memcheck --log-file=vg-affected.log \
  path/to/node-v24.22.2-linux-x64/bin/node \
  lab/repro/node2shell-rung1-server.js 0 &      # reads LISTEN <port> from stdout
node lab/repro/node2shell-rung1-client.js <port> 1040
# then kill the valgrind server; vg-affected.log has the Invalid write
# of size 1 (WriteOneByteV2 <- Http2Session::AltSvc); repeating with
# node-v24.22.3 gives ERROR SUMMARY: 0.
```

Harness: `lab/repro/node2shell-rung1-server.js` (HTTP/2 server on
127.0.0.1 forwarding `:authority` into `session.altsvc` — the advisory's
app precondition) and `lab/repro/node2shell-rung1-client.js`
(single request, syntactically valid long authority, waits for the
ALTSVC frame echo proving the full path executed). Both committed.

## Lab provenance

- First wake: nodejs.org source tarball `node-v24.22.2.tar.gz` (117 MB);
  `apt-get install clang` → clang 18.1.3 (08:46Z); tagged-source
  fetches from raw.githubusercontent (provisioning, no probing).
  ASan build attempt abandoned (killed at wake boundary; see negative
  result above).
- Second wake (2026-11-20 08:56Z): nodejs.org prebuilt
  `node-v24.22.2-linux-x64.tar.xz` and `node-v24.22.3-linux-x64.tar.xz`
  (sha256 recorded below); Valgrind 3.22.0 already present on host.

  ```
  48cc0e21e048790e54c0cf5749c2725005313d652651c40b7a21feb9697aaf75  node-v24.22.2-linux-x64.tar.xz
  4f2b175a6d53a5c617a80dba2676238a0688cef28c6da4eba35c7d844e66fcfb  node-v24.22.3-linux-x64.tar.xz
  ```
