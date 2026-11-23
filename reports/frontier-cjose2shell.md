# Frontier brief: cjose AES Key Wrap `encrypted_key` heap overflow (cjose2shell)

**STAGED 2026-11-23 W180** — this brief, a direct-call rung-1..4 harness and a
registered two-pane window exist. Pinned source, hashes and full negatives are
in `lab/frontier/cjose2shell/PROVENANCE.md` and `PINS.sha256`; the harness is
`lab/frontier/cjose2shell/harness/{run.sh,check.sh,driver.c}`. The harness
calls the real `cjose_jwe_import()` / `cjose_jwe_decrypt()` path in a real
cjose build against a real compact JWE, not a source slice.

Window 124, inner socket, two live panes verified at 19:55Z (tail pid 1238556,
plant_view pid 1238772); registry 125/125; seed wall
`.mishe-tauftauf/walls/cjose2shell.md`. Charter and wake units are owed from
operator admission and the person's full-flag sync.

Clean offline `git archive 841b716` replay: 73 files, 7/7 pins, 8 binaries
rebuilt from committed tarballs, `PASS=223 FAIL=0` with the exact same trace;
see `lab/frontier/cjose2shell/REPLAY.md`. Witness replay is still owed.

## 1. Verified ground truth

- Source claim: GHSA-75r7-f5cv-g3wj / CVE-2026-53938, GitHub Advisory
  Database, published 2026-06-02, High CVSS 8.2
  (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`), CWE-122 and CWE-787.
  It describes a heap OOB write in the AES Key Wrap JWE decryption path for
  `alg = A128KW/A192KW/A256KW`, reachable pre-authentication through
  `cjose_jwe_import()` / `cjose_jwe_decrypt()` on fully attacker-controlled
  compact JWE input. The advisory's "may be leverageable" RCE prose is a
  **claim**, not reproduced here.
- Affected: cjose `<= 0.6.2.4`; patched `>= 0.6.2.5`. The vulnerable source
  is tag `v0.6.2.4`, raw `src/jwe.c` SHA-256
  `a6945f0a70033272ddfd9c6a9ec38cf44b7810785930302317d5fc29a5e387e6`.
- Fix: commit `8c51d245273583a658f24ef7b08ba22f848a34a5` (parent
  `d2825697c4ce9edec1ee5f08509bba6a2df20e28`), a 9-line length check. The
  lab "fixed" tree is v0.6.2.4 plus **only** that `src/jwe.c` hunk
  (SHA-256 `9b45915478ad87c929a7050551434b9d21461dcf6dbcf890efa916409f49870b`);
  upstream `v0.6.2.5` was fetched and contains the same check.
- No external probe. Advisory, patch, source and dependency fetches were
  provisioning only; all runtime work was local.

## 2. Source-bound mechanism and fix

From pinned vulnerable `src/jwe.c:589-603`:

```
if (jwk->kty != CJOSE_JWK_KTY_OCT) return false;              // :584
...
if (!jwe->fns.set_cek(jwe, NULL, false, err)) return false;    // :591-594
int len = AES_unwrap_key(&akey, NULL, jwe->cek,
                         recipient->enc_key.raw,
                         recipient->enc_key.raw_len);          // :595-596
if (len <= 0) { CJOSE_ERROR(err, CJOSE_ERR_CRYPTO); return false; }
jwe->cek_len = len;                                            // :602
```

`set_cek()` for `enc=A128CBC-HS256` allocates exactly 32 bytes
(`_cjose_jwe_set_cek_aes_cbc()`, pinned `:455-470`). OpenSSL's
`AES_unwrap_key()` copies `raw_len-8` transformed bytes into `jwe->cek`
before checking RFC 3394 integrity. `recipient->enc_key.raw_len` comes from
the length of the compact JWE's second (base64url) segment, which the
attacker controls; there was no `raw_len == cek_len + 8` check. The fix adds
exactly that check with `CJOSE_ERR_INVALID_ARG` before the `AES_unwrap_key`
call.

## 3. Cheapest local experiment

Build pinned cjose v0.6.2.4 with and without the fix hunk, plus a locally
built jansson 2.14 (the host has no jansson headers). The driver creates a
valid A128KW/A128CBC-HS256 compact JWE with the upstream test key, replaces
the encrypted_key segment with an attacker-sized base64url blob, and calls
the real import and decrypt entry points. Scenarios: `valid` (40-byte wrap),
`odd` (41 bytes, OpenSSL length rejection), `probe` (48 bytes, invalid IV),
`wrapped` (48-byte RFC 3394 wrap of a 40-byte chosen plaintext), `wrappedbig`
(1024-byte wrap), `undersized` (32 bytes). Eight binaries: gcc/clang x
vulnerable/fixed x ASan/plain. The `wrapped` case is the material one: an
RFC 3394-valid wrap makes unwrap succeed, so the chosen bytes are not
cleansed by a failed integrity check.

Run from `lab/frontier/cjose2shell/harness/`: `./run.sh` verifies pins and
builds; `./check.sh` runs 48 invocations plus one gdb probe and prints a
normalized trace hash.

## 4. Observed evidence (W180, direct call into a real library)

- Rung 1 / determinism: `valid` decrypts the 15-byte upstream plaintext in
  all 8 binaries; every tampered token still imports (`IMPORT=1 ERRCODE=0`).
- Rung 2: vulnerable `wrapped` reports `CEK_LEN_AFTER=40` on a 32-byte
  allocation, and the first 32 bytes equal the independently computed
  transform (`CEK_CMP_LEN=32 MISMATCHES=0`). Fixed `wrapped` returns
  `DECRYPT=0 ERRCODE=1` (invalid argument) with `CEK_LEN_AFTER=32`.
- Rung 3: gcc and clang ASan both report `heap-buffer-overflow`,
  `WRITE of size 40` for `wrapped` and `WRITE of size 1016` for
  `wrappedbig`, with the 32-byte allocation from `_cjose_jwe_malloc` at
  pinned `jwe.c:193` and the copy inside OpenSSL's `memmove`. All fixed ASan
  runs are clean; `odd` and `undersized` produce no ASan report.
- Rung 4: gdb on `gcc-vulnerable-plain wrapped`, at the library's
  `AES_unwrap_key` call (`jwe.c:595`), `inlen=48`, destination `jwe->cek`.
  After the call the heap reads 32 x `5a` then
  `4d 49 53 48 45 2d 4f 4f` ("MISHE-OO") at `cek+32..39` — lab-chosen
  bytes at chosen offsets past the declared 32-byte object.
- Plain vulnerable `wrappedbig` aborts in glibc `free(): invalid pointer`
  (rc 134), preserved as heap-corruption evidence; the invalid-IV `probe`
  is a negative for chosen bytes because OpenSSL cleanses its output after
  the integrity failure, though its out-of-bounds write is still caught by
  ASan.
- `harness/check.sh`: **223 PASS / 0 FAIL** on three identical runs, trace
  `455b84940f98bf273d7007f8a054c4ff7f1b37017fd6afa7207a1bdb338e9da7`.

## 5. W181 loopback wire consumer (measured W181, variation cause resolved W183)

A lab-only consumer (`lab/frontier/cjose2shell/w1/{server.c,client.py,build.sh,run.sh}`)
binds an ephemeral port on 127.0.0.1, accepts a real HTTP GET carrying a
tampered compact JWE in `Authorization: Bearer`, decodes the encrypted_key
segment from the wire, and calls real `cjose_jwe_import()` /
`cjose_jwe_decrypt()` in the pinned vulnerable, fixed and ASan builds. The
client generates RFC 3394 wraps locally with the same lab KEK. Results in
`w1/evidence/`; length propagation and ASan findings were stable across three
replays, but the plain 56-byte outcome varies by build/run (below).

- Wire length propagates: 48-, 56-, 64- and 1024-byte wrapped segments reach
  the copy and yield `CEK_LEN_AFTER=40/48/56/1016` on the 32-byte CEK in vulnerable
  builds; fixed builds reject with `ERRCODE=1` and keep 32. ASan reports the
  `jwe.c:595` write in each tampered case.
- Plain glibc result depends on the write size: 40 bytes stay inside the
  chunk's 40 usable bytes and exit cleanly; 48 bytes corrupt the adjacent
  chunk's size field and abort in `munmap_chunk()` (rc 134); 1016 bytes
  segfault (rc 139). The 56-byte case is not stable: the author's first
  three runs and most repeats exited 0 with `CEK_LEN_AFTER=56`, while an
  independent clean-room witness replay saw rc 139 on its first run, 10/10
  rc 0 on plain repeats and 2/10 rc 139 on the trace build. The author's own
  W182 replay (`w1/evidence/wrappedN56-variation-w182.log`) saw 2/12 rc 139
  on plain and 1/12 rc 139 on trace. The witness traced one rc 139 crash to
  `__strcmp_avx2` via `_cjose_jwe_calc_auth_tag` (`jwe.c:1098`) through
  `_cjose_jwe_decrypt_dat_aes_cbc` (`jwe.c:1400`) with `enc=0x0`, consistent
  with an overflow-corrupted live jansson string reaching the real decrypt
  path. W183 established why it varies
  (`w1/evidence/wrappedN56-cause-w183.log`): the adjacent 25-byte jansson
  object is a `json_string_t`, and with an identical allocation ring it is
  either the 13-byte `enc` value or the 6-byte `alg` value in different
  processes. In a 40-run instrumented batch all 4 crashes had
  `json_object_get(hdr,"enc")` returning that object and all 36 survivors did
  not; the 56-byte write replaces its `type` with chosen byte `0x5a`, so
  `json_string_value()` returns NULL and the real decrypt path faults in
  `strcmp`. Chosen bytes `02 00 00 00 01 00 00 00` (valid type and refcount)
  removed that fault in all 60 runs, but all then aborted in `munmap_chunk()`
  because the chunk size at `cek+40..47` is still corrupted. Fixed-IV and
  ASLR-off batches still vary. Pinning jansson's per-process hash seed makes
  the outcome deterministic per seed (`w1/evidence/wrappedN56-hashseed-w183.log`):
  seeds 19, 27 and 30 gave rc 139 in 6/6 runs each with `enc` adjacent; the
  other 37 tested seeds gave rc 0 with it elsewhere. No pointer or control-flow
  target; security grade and rung 1-4 ceiling unchanged.
- Heap map: the CEK is a 48-byte glibc chunk; the adjacent object is a
  25-byte jansson `jsonp_malloc` string at `cek+48`, preceded by its size
  field at `cek+40`. Further neighbors come from jansson, `_decode`,
  `_cjose_strndup` and `_oct_new` (symbolized in `PROVENANCE.md`).
- Source-only check of an unbuilt mod_auth_openidc v2.4.15.1, corrected in
  W184: the backchannel-logout POST path (`mod_auth_openidc.c:3960-3967`
  dispatch, `:3154-3182` handler, `jose.c:930-936`, `:765-771`) does call
  `oidc_jwt_parse()` before signature validation, but its key set is
  `oidc_util_merge_symmetric_key(r->pool, cfg->private_keys, NULL)` and
  `cfg->private_keys` is populated only from PEM RSA/EC keys
  (`config.c:879-905`); cjose rejects non-OCT JWKs for AES-KW
  (`jwe.c:574-579`). That path therefore does not supply an OCT KEK to the
  vulnerable unwrap. A different pre-signature path does:
  `proto.c:1426-1434` builds an OCT JWK from `provider->client_secret` and
  calls `oidc_jwt_parse()` -> `oidc_jwe_decrypt()` -> `cjose_jwe_decrypt()`
  with no encrypted_key length check, but it needs a matching `state` cookie
  from an earlier authorization request (`mod_auth_openidc.c:2116-2118`),
  so it is not a single unauthenticated POST. Both remain source claims about
  an unbuilt consumer: no running deployment, witness replay or byte-value
  claim; in a real deployment the KEK is secret, so only length is
  attacker-chosen.
- W184 measured negative for that real consumer (`lab/frontier/cjose2shell/w2/`):
  a real mod_auth_openidc 2.4.15.1 Apache module, built against pinned
  vulnerable cjose v0.6.2.4 and run on 127.0.0.1:18443, was sent an
  unauthenticated backchannel-logout POST with a 56-byte raw `encrypted_key`
  (`raw_len=56 > cek_len+8=40`). With a `kid` matching the configured PEM RSA
  key, gdb logs `W2_CJOSE_JWE_DECRYPT_REACHED jwk_kty=1` and
  `W2_AES_KW_DECRYPT_REACHED raw_len=56 cek_len=0 jwk_kty=1`, but no
  `AES_unwrap_key()` breakpoint hit: cjose rejects the non-OCT JWK at
  `jwe.c:577` before the vulnerable copy. Without `kid`, no decrypt call
  occurs. A 40-byte correct-length control is rejected at the same `jwe.c:577`
  line, so the rejection is key type, not length; all three POSTs returned
  HTTP 400. Exact module/library hashes, request/response bytes, Apache log
  and replay commands are in `w2/README.md` and `w2/evidence/`. This is a
  measured negative for AES-KW on the default backchannel key configuration,
  not a witness verdict and not a rung-5 result; the id_token path with an
  OCT JWK from `client_secret` remains an unmeasured source-level follow-up.

## 6. Honest ceiling

Direct call plus a loopback-only synthetic consumer, with a real compact JWE
token and a lab-known symmetric key. Wire-length control and heap adjacency
are measured. The witness independently replayed both lanes from a clean
git archive: rungs 1-4 ESTABLISHED at the labeled direct-call real-library
scope, and rungs 1-3 plus byte-control mechanics ESTABLISHED at the labeled
synthetic 127.0.0.1 consumer scope (the 56-byte wording contradiction from
that replay is amended and its cause measured in section 5). W184 built and
ran a real mod_auth_openidc module on loopback: the oversized AES-KW
encrypted_key reaches the vulnerable helper but the key-type precondition
for the copy is absent in that path (section 5), so it is a measured
negative, not deployed reachability of the corruption. No deployed server,
credential, pointer/IP control or shell command. Advisory pre-authentication
reachability in a real deployment and any RCE claim remain **UNKNOWN**;
rung 5 not attempted and not established. A pointer or control-flow target
in a real consuming process is the prerequisite for any benign-marker
attempt.
