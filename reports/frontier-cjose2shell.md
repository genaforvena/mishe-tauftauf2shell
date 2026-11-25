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
see `lab/frontier/cjose2shell/REPLAY.md`. The witness independently replayed
the direct-call and W181 wire lanes from a clean archive (verdicts #3019/#3020)
and the W188 groomed function-pointer limb (ESTABLISHED AS LABELED, #3566);
see section 5.

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
  so it is not a single unauthenticated POST. At W184 both were source
  claims; W186 measured the id_token lane with a lab OCT `client_secret` and
  a matching state cookie (below). In a real deployment the KEK is secret,
  so only length is attacker-chosen.
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
  HTTP 400. Build-instance module/library hashes (the `-g` build path makes
  them differ across build directories), request/response bytes, Apache log
  and replay commands are in `w2/README.md` and `w2/evidence/`. This is a
  measured negative for AES-KW on the default backchannel key configuration;
  the witness independently replayed it from a clean archive and ESTABLISHED
  it at the labeled real-consumer / loopback scope (DM #3079). It is not a
  rung-5 result.
- W186 measured the id_token lane in the same real mod_auth_openidc build
  (`w2/`): `apache-idtoken.conf` adds `OIDCClientSecret` (OCT JWK derived as
  SHA-256(secret)[:16]), `OIDCResponseType id_token` and
  `OIDCResponseMode form_post`. `probe-idtoken.py` first GETs `/private` with
  `Accept: text/html`, capturing the 302 `state` and encrypted state cookie,
  then POSTs a compact JWE `id_token` with a 56-byte raw `encrypted_key` to
  `/redirect_uri`. gdb logs `W2I_PARSE_IDTOKEN_REACHED`,
  `W2I_CJOSE_JWE_DECRYPT_REACHED jwk_kty=3` (OCT),
  `W2I_AES_KW_DECRYPT_REACHED raw_len=56 cek_len=0 jwk_kty=3` and
  `W2I_AES_UNWRAP_KEY_REACHED`; the 32-byte CEK receives 48 bytes. The
  response was HTTP 400 (integrity failure), but a later loopback request
  aborted the Apache process in glibc `free(): invalid next size (fast)` at
  `jansson jsonp_free -> json_delete_string -> json_decref ->
  oidc_proto_state_destroy` (full backtrace in
  `w2/evidence/gdb-idtoken-crash-final.log`). A 40-byte correct-length
  control reached `AES_unwrap_key()` in the same configuration with no abort
  (`w2/evidence/gdb-idtoken-abort.log`). All listeners were on
  127.0.0.1:18443 and stopped after capture; raw bytes, tokens, logs and
  hashes are in `w2/evidence/` (`idtoken-SHA256SUMS`). This is measured
  pre-signature reachability of the corruption in a real consumer with a
  lab-configured KEK and a state cookie, not deployed reachability and not
  r5. The witness has not replayed this lane.

- W187 moved chosen bytes into the same real consumer. `w2/probe-idtoken-chosen.py`
  wraps a 56-byte chosen plaintext with the config-derived OCT KEK
  (`SHA-256(client_secret)[:16]`), so RFC 3394 integrity passes and the chosen
  bytes survive; the raw `encrypted_key` is 64 bytes. Three 127.0.0.1:18443
  runs each logged `W2C_AES_KW_DECRYPT_REACHED raw_len=64 ... jwk_kty=3` and
  `W2C_UNWRAP_ENTRY inlen=64`: 56 bytes copied into the 32-byte CEK. The
  pre-unwrap dump shows the CEK chunk header (`cek-16`) size `0x31` and the
  following top-chunk size at `cek+40..47` (`0x1bd41` twice, `0x1be71` once);
  the post-unwrap dump confirms chosen bytes at `cek+32..55`. With
  `0x0606060606060606` there (`valid`, `invalid`) the POST aborted inside
  HMAC at `jwe.c:1158` with glibc `malloc(): corrupted top size`; with
  `0x1bd41` written over an observed `0x1be71` (`preserve`), the POST returned
  HTTP 400 and the follow-up GET aborted in jansson `string_create ->
  jsonp_malloc(32)` with `malloc(): unaligned tcache chunk detected`. Chosen
  bytes at chosen offsets therefore select the allocator check and fault site
  in a real mod_auth_openidc process. `enc` was elsewhere in all three runs
  (delta -0xF80, -672, -3968 from the CEK), so no live header string was
  corrupted at `cek+48`: no code pointer in the write, no pointer/IP control,
  no marker, no r5. Raw bytes, tokens, logs and hashes:
  `w2/evidence/chosen64-*` and `w2/evidence/chosen64-SHA256SUMS`. The empty
  `*-post.bin` / `*-follow.bin` files record aborts before a response. The
  witness has not replayed this lane.

- W188 tested the pointer-target question in two bounded lanes. In the real
  consumer, `w2/gdb-idtoken-scan.cmd` plus `w2/probe-idtoken-scan.py` dumped
  2 KiB after the CEK at unwrap entry and at auth-tag calculation with the
  process mappings (`w2/evidence/gdb-idtoken-scan.log`): in that run all 512
  words were outside every executable and heap mapping, so that default
  layout had no live pointer-bearing object in the forward region. W195
  extended the same lane to 8 KiB (`w2/gdb-idtoken-wide.cmd`,
  `w2/probe-idtoken-wide.py`, `evidence/gdb-idtoken-wide.log`): 3 of 1024
  words sat in libc mappings at `cek+32/+112/+136`, but the header at
  `cek+40` is the `0x1bd41` top-chunk size, so they are stale FILE/vtable
  remnants in free space, not live objects. Forward contents vary by run;
  no run has shown a live pointer behind the CEK. In a separate groomed
  direct-call lab process, `fptr/{driver.c,run.sh}` placed the real OCT JWK
  720 bytes after the reused 32-byte CEK chunk; a 776-byte raw
  `encrypted_key` (768-byte RFC 3394-valid wrap) preserved every JWK field
  except `fns`, which was set to a lab fake table with a benign marker as
  `free_func`. The real `cjose_jwk_release()` invoked it:
  `BENIGN_MARKER_EXECUTED` / `MARKER_CALLED=1` in the vulnerable build,
  5/5 repeats; vulnerable safe input and both fixed controls stayed at 0
  (3/3 fixed repeats). The wrap carries an absolute lab-chosen address, ASLR
  is not defeated, decrypt returns `CJOSE_ERR_CRYPTO` and the corrupted JWE
  teardown is skipped; there is no wire path to this layout, no command and
  no r5. Evidence: `fptr/evidence/`, `PROVENANCE.md` W188. W192 replayed this
  lane from a clean `git archive 1212b10` (offline rebuild, `PASS=223 FAIL=0`):
  all four outputs match the committed evidence after address normalization,
  with 5/5 vulnerable marker calls and 0/3 fixed calls. W193 reduced that
  replay to one offline command, `replay-w188.sh` (pins, jansson and all six
  cjose trees rebuilt from committed tarballs, `check.sh`, `fptr/run.sh` and
  control assertions); from a clean archive it printed `REPLAY_W188_OK` with
  the same `PASS=223 FAIL=0` trace and byte-identical normalized outputs.
W194: the witness independently replayed this W188 limb from a clean
`git archive 8c717a2` and returned **ESTABLISHED AS LABELED** (#3566). Its
clean room checked 7/7 pins, `REPLAY_W188_OK` and the exact trace hash
`455b84940f98bf273d7007f8a054c4ff7f1b37017fd6afa7207a1bdb338e9da7`;
vulnerable fptr showed `GROOM_OK=1`, `CEK_LEN_AFTER=768`,
`JWK_FNS_NOW==FAKE_FNS`, `BENIGN_MARKER_EXECUTED` and `MARKER_CALLED=1`,
while vulnerable safe and both fixed controls stayed at 0 (10/10 fresh
vulnerable repeats, 0/5 fixed); normalized output hashes match the committed
W188/W193 evidence. The witness also steered a second marker in a throwaway
driver copy: `CHOSEN_FNS 0x...3020` fired marker 1 and `0x...3040` fired
marker 2, showing the call followed the chosen pointer. Grade and ceiling are
unchanged: lab-known absolute address, groomed direct-call process, benign
marker through real `cjose_jwk_release()`, no wire path, no ASLR defeat, no
command and no r5. W186/W187 remain separate author-only offers.

- W199 extended the loopback lane to a live pointer field. `w1/ptr-client.py`
  sends a real HTTP GET whose 80-byte `encrypted_key` wraps 72 chosen bytes:
  the JSON_STRING type/refcount of the object at `cek+48` is preserved, its
  next-chunk size at `cek+40` is preserved, and its value pointer at
  `cek+64..71` is set to `41` x 8. Under gdb the process faults in
  `__strcmp_avx2` from `_cjose_jwe_calc_auth_tag` (`jwe.c:1098`): gdb shows
  `enc=0x4141414141414141` and `rdi=0x4141414141414141`, i.e. a wire-derived
  pointer reaches a control-flow-relevant argument in a real decrypt call.
  8/40 plain repeats faulted (jansson's random `hashtable_seed` decides
  whether the adjacent string is `enc`); the baseline without the
  type-preserving bytes faulted with `enc=0x0` instead. The fixed build
  rejects the same token before the write (`ERRCODE=1`, `CEK_LEN_AFTER=32`),
  and safe tokens keep `CEK_LEN_AFTER=32`. The value is a recognizable
  non-address: no valid pointer, ASLR defeat, command or wire-derived live
  address, so this is an author-only, stronger rung-4 limb, not r5. Evidence:
  `w1/evidence/w199-gdb/ptr72-3.log`, `w1/evidence/w199-controls/`,
  `w1/evidence/w199-rep/`, `w1/evidence/W199-SHA256SUMS`; replay details in
  `PROVENANCE.md` W199. W201 added a one-command clean-archive replay
  (`replay-w199.sh`, receipt `REPLAY-W199.md`): `REPLAY_W199_OK`, the exact
  `PASS=223 FAIL=0` trace, 7/8 vulnerable runs at `CEK_LEN_AFTER=72`, and a
  captured `enc=0x4141414141414141` / `rdi=0x4141414141414141` strcmp fault.
  That is author replay of committed bytes, not a witness verdict; the one
  command is now offered on the chat tape.

- W202 turned W199's wire-chosen non-address into a *valid* pointer. The
  `-no-pie` `w1-trace-vuln` build fixes the cjose literal
  `"A128CBC-HS256"` at `0x41bd2e`; `w1/ptr-client.py` now takes an optional
  little-endian pointer, so the real HTTP token carries
  `2e bd 41 00 00 00 00 00` at plaintext offset 64. Under gdb in
  `_cjose_jwe_calc_auth_tag`, the successful run shows
  `enc=0x41bd2e "A128CBC-HS256"`, `x/s enc` prints the literal, `strcmp`
  succeeds, the process exits normally with `DECRYPT=0 ERRCODE=4
  CEK_LEN_AFTER=72`, and the HTTP reply is the ordinary 401. The same
  build/token with `0x4141414141414141` faults in `__strcmp_avx2` at
  `jwe.c:1098`; the fixed build rejects the valid-pointer token with
  `ERRCODE=1`/`CEK_LEN_AFTER=32`; the safe token keeps `CEK_LEN_AFTER=32`.
  Jansson's random seed decides whether the adjacent string is `enc`
  (W183), so `w1/validptr-run.sh` retries 1/11 valid-pointer attempts and
  1/16 baseline attempts hit that adjacency; no run with the valid address
  faulted. Evidence: `w1/evidence/w202-validptr/` and `W202-SHA256SUMS`
  (33 files, `sha256sum -c` OK). The address is build-known, not leaked or
  wire-derived from a live target; heap/PIE ASLR is not defeated, there is
  no command or control-flow marker, and the real mod_auth_openidc lane
  still has top chunk after the CEK (W189). Grade unchanged; author-only
  rung-4 limb.
  `replay-w202.sh` replayed these committed bytes from a clean `git archive`
  (`1c5a584a`): pins OK, exact `PASS=223 FAIL=0` trace, `W202_VALIDPTR_OK`
  and `REPLAY_W202_OK` with the same `0x41bd2e` literal dereference. Author
  replay only; the one command is offered to witness.

- W203 carried a chosen function pointer on a real HTTP request into the
  loopback consumer. `w1/wmarker/` is a copy of the w1 server with a static
  `key_fntable` whose `free_func` prints `BENIGN_MARKER_EXECUTED`, plus a
  32-byte grooming hole allocated before the OCT JWK and freed before
  decrypt so the vulnerable CEK reuses it (JWK at CEK+720, `fns` at
  CEK+760). The client wraps a 768-byte RFC 3394-valid plaintext; chosen
  bytes preserve the adjacent JWK fields and replace only `fns` with the
  fixed `-no-pie` fake-table address `0x4213e0`. The vulnerable run printed
  `GROOM_OK=1 JWK_FNS_NOW=0x4213e0`, `BENIGN_MARKER_EXECUTED`,
  `MARKER_CALLED=1`; the fixed build rejected before the copy with
  `ERRCODE=1`/`CEK_LEN_AFTER=32` and `MARKER_CALLED=0`; a safe token left
  `MARKER_CALLED=0`. Layout was stable across the bounded retries. Evidence:
  `w1/wmarker/evidence/` with `WMARKER-SHA256SUMS` (24 files, verified).
  Limits: the called address is a fixed lab binary address; the preserved
  `keydata` field comes from the server's lab stdout, not from the wire;
  the fixed control reuses the same attack *parameters*, not byte-identical
  heap-dependent tokens. PIE/heap ASLR is not defeated, decrypt fails, no
  command or shell runs, the real consumer still has top chunk after the
  CEK (W189), so grade and r5 ceiling are unchanged. Author-only limb,
  offered to witness; `sh w1/wmarker/run.sh` printed `WMARKER_OK` on an
  independent author rerun.
  `replay-w203.sh` from a clean `git archive` (`e9a1c09a`) printed
  `REPLAY_W203_OK` with the same pins, exact direct-call trace and marker
  result. Author replay only; offered to witness as #3861.

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
negative, not deployed reachability of the corruption; the witness replayed
that lane from a clean archive and ESTABLISHED the negative at the labeled
real-consumer / loopback scope (DM #3079). W186 used the same build with a
lab OCT `client_secret` and a matching state cookie: the id_token lane
reached `AES_unwrap_key()` and the process aborted in glibc `free()`;
the 40-byte control reached unwrap without abort (section 5). W187 used a
config-derived KEK so the chosen wrap bytes survive the integrity check:
64-byte raw keys reached unwrap in the real consumer and chosen bytes at
`cek+40..47` selected between two glibc allocator aborts (section 5). That
is chosen-byte control of a fault site in a real process; `enc` was never
adjacent to the CEK in those runs. W188 found no pointer in the real
consumer's forward 2 KiB, but in a groomed direct-call process the same
overflow rewrote a live JWK `fns` pointer and a lab-chosen benign marker was
called by the library; that needs an absolute lab-known address and has no
wire path. The witness independently replayed that W188 limb from a clean
archive and ESTABLISHED it AS LABELED (#3566): rung-4 mechanics in a groomed
direct-call process, not a deployed path. No deployed server, real credential,
address leak or shell command. W212 now measures **lab pre-auth reachability**
in a real consumer (no cookie, no POST, no prior request). Advisory
reachability in a real deployment and any RCE claim remain **UNKNOWN**;
rung 5 not attempted and not established.

W190 checked a jansson length-corruption info-leak hypothesis against the
pinned object layout and the W183 heap log: the string's `value` pointer sits
at object `+16` and its length at `+24`, so the contiguous write must destroy
the ASLR-randomized pointer before it can reach the length. No wire-visible
pointer source; no new experiment or rung.

- W196 tested the remaining tcache-poisoning hypothesis with a lab-only
  `--wrap=free` driver on the pinned plain libraries (`fptr/cleanse.c`,
  `fptr/cleanse-run.sh`). Vulnerable attack with a 40-byte chosen wrap had
  `5a`x32 + `MISHE-CL` at `cek+0..39` before release, but
  `_cjose_release_cek()` (`jwe.c:72-83`) zeroes `cek_len` bytes before
  `free()`: all 40 bytes were zero at `free()` entry, with the next-chunk
  size at `+40` unchanged. Vulnerable safe, fixed attack and fixed safe
  controls were also zero at free. No attacker-chosen byte reaches tcache
  `next`/`key`, so tcache steering is a structural negative; RFC 3394's
  8-byte write granularity likewise rules out partial pointer overwrites on
  16-byte-aligned glibc objects. No new rung, address leak, command or r5.
- W197 swept the attacker-controlled `enc` header, which selects CEK sizes
  16/24/32/48/64 in the pinned `set_cek` (all earlier work used only the
  32-byte A128CBC-HS256 CEK). In 80 lab-only direct-call cases (`harness/
  enc-driver.c`, `evidence/enc197/`), safe wraps decrypt in all four
  vulnerable/fixed gcc plain/ASan builds; every oversized case in vulnerable
  builds writes `raw_len-8` bytes and reports `CEK_LEN_AFTER = raw_len-8` on
  the enc-selected allocation, while all fixed oversized cases reject with
  `ERRCODE=1`. ASan confirms the same `jwe.c:595` write for 16/24/32/48/64-
  byte regions. A new gcm192 fault site is a glibc `free()` inside libcrypto
  `EVP_CIPHER_fetch` from `_cjose_jwe_decrypt_dat_aes_gcm` (`jwe.c:1323`),
  caused by a corrupted next-chunk size, not a pointer. The fix generalizes
  to every `enc`; changing CEK size exposes no wire-derived pointer, so the
  grade and ceiling are unchanged.
- W198 closed the missing fixed-cjose control in the real-consumer id_token
  lane (W186). A second mod_auth_openidc 2.4.15.1 `.so`, statically linked
  against the pinned v0.6.2.4 + `8c51d245` library, was replayed against the
  same loopback wire bytes as the vulnerable build. In the vulnerable run,
  `AES_unwrap_key` was reached with `raw_len=40` and `raw_len=56`; the
  oversized POST returned HTTP 400 and the follow-up GET aborted Apache in
  `free(): invalid next size (fast)` via `oidc_proto_state_destroy`. In the
  fixed run only `raw_len=40` reached the unwrap; `raw_len=56` was rejected
  with `CJOSE_ERR_INVALID_ARG` at the fixed `jwe.c:599` length check, and the
  follow-up GET returned `HTTP/1.1 302 Found` with no abort. Evidence:
  `lab/frontier/cjose2shell/w2/evidence/gdb-idtoken-{vulncontrol,fixed}.log`
  and `W198-SHA256SUMS`. This confirms the 9-line fix removes the observable
  real-consumer corruption; no pointer, command, address leak or wire-derived
  address appeared, so the grade and rung-5 ceiling are unchanged. The
  witness has not replayed this lane.
- W211 checked a caller-census claim from awslc2shell W214 (chat #17028,
  commit `bf2a32ff`) against the pinned vulnerable `src/jwe.c:1451-1468`
  directly. The CBC decrypt allocates `jwe->dat` as `p_len + AES_BLOCK_SIZE`,
  writes it with one `EVP_DecryptUpdate`, then appends with
  `EVP_DecryptFinal_ex` at `jwe->dat + p_len`; the only two-update path is
  GCM AAD with `out=NULL`. So there is no adjacent padded two-update output
  buffer here that could carry a control datum. This is a source-scope
  structural negative corroborating the W189/W195 heap scans, not a wire
  result: no grade change, no r5.
- W212 measured the advisory's pre-auth reachability claim inside the lab
  consumer, without a cookie, POST, state or prior request. Source route in
  the pinned local mod_auth_openidc 2.4.15.1 tree: `src/oauth.c:578`
  `oidc_oauth_validate_jwt_access_token()` makes an OCT JWK from
  `OIDCClientSecret`, `:592` calls `oidc_jwt_parse`, and `jose.c:1144` calls
  `cjose_jwe_import()`/`cjose_jwe_decrypt()`; `oidc_alg2kty()` (`jose.c:225`)
  maps A128KW to OCT. In real Apache on 127.0.0.1:18444 with `AuthType
  oauth20`, one `GET /private` carrying an `Authorization: Bearer` compact
  JWE with a 56-byte raw `encrypted_key` logged
  `W2B_AES_KW_DECRYPT_REACHED raw_len=56 cek_len=0 jwk_kty=3` and
  `W2B_AES_UNWRAP_KEY_REACHED`; the response was HTTP 401 after integrity
  failure. With the lab config's 16-byte KEK and an RFC 3394 wrap of
  `MISHE-W212-` x 4 + `MISH`, gdb at vulnerable `jwe.c:602` saw
  `cek_len_before=32` and all 48 chosen bytes at `jwe->cek[0..47]`. The
  statically fixed-cjose module on 127.0.0.1:18445 rejected the same 56-byte
  wire token with `CJOSE_ERR_INVALID_ARG` at `jwe.c:599` before unwrap; its
  40-byte control reached unwrap and failed integrity at `:608`. Two failed
  setups are preserved: a missing `OIDCRedirectURI` prevents Apache startup,
  and a 29-byte client secret fails `AES_set_decrypt_key` at pinned
  `jwe.c:585` before unwrap. `sh
  lab/frontier/cjose2shell/w2/run-oauth-bearer.sh` replays all three lanes in
  9 PASS / 0 FAIL; three live-tree runs were identical, and a clean
  `git archive 35e02887` replay with the four pinned untracked build trees
  copied in was also 9 PASS / 0 FAIL, no listener left. This is rung-4
  pre-auth reachability and chosen-byte control in a real consumer at the
  labeled loopback/lab-KEK scope. It is not deployed
  reachability: the lab config supplies the OCT KEK, ASLR is not defeated,
  there is no pointer/IP target, benign command or wire-derived address, and
  the witness has not replayed it. No grade change or r5.
