# w2 — real mod_auth_openidc / cjose loopback measurements (2026-11-23, UTC)

## Verdict (measured, negative for exploitability on this path)

A real `mod_auth_openidc` 2.4.15.1 Apache module, built against pinned vulnerable
`cjose` v0.6.2.4, **does** reach `cjose_jwe_decrypt()` and then
`_cjose_jwe_decrypt_ek_aes_kw()` with an attacker-controlled compact-JWE
`encrypted_key.raw_len = 56 > cek_len + 8 (= 40)` on an unauthenticated loopback
backchannel-logout POST — **but only when the JWE header carries a `kid` matching
the one configured RSA private key**. The vulnerable `AES_unwrap_key()` call is
**not reached**: cjose rejects the non-OCT JWK first (`jwe.c:577`), so there is no
overflow, fault, or corruption. With the stock no-`kid` form, decryption-key
selection skips the RSA key and `cjose_jwe_decrypt()` is not called at all.
Both overlong and correct-length controls return HTTP 400.

This upgrades the source-only claim to a measured negative with one nuance:
the attacker-controlled oversized `encrypted_key` does enter the vulnerable
AES-KW helper, but the key-type precondition for the overflow is absent in the
default backchannel-logout key configuration. **No rung-5/RCE claim.**

## Versions / artifacts

* Apache `2.4.58 (Ubuntu)`, `Server built: 2026-11-12T12:58:56`.
* Module: `mod_auth_openidc-2.4.15.1`, built from the local pinned source tree,
  loaded from `w2/mod_auth_openidc/.libs/mod_auth_openidc.so`.
  Startup log: `mod_auth_openidc-2.4.15.1 - init - cjose 0.6.2.4, openssl-3.0.13, EC=yes, GCM=yes, Memcache=yes, Redis=no, JQ=no`.
* cjose v0.6.2.4 copied to `w2/cjose-vuln`, rebuilt PIC/static with
  `CFLAGS='-g -O0 -fPIC -fno-omit-frame-pointer'`, linked to the harness
  jansson 2.14 prefix.
* Hashes: `evidence/SHA256SUMS`. The `.a`/`.so` entries are build-instance
  values for this checkout path: `-g` embeds the build directory, so a replay
  elsewhere produces different library/module hashes (seen in the witness's
  `/tmp` replay, DM #3079). Tokens, private key and wire bytes are stable.
* Listener: `127.0.0.1:18443` only; private Apache started with `-X -f w2/apache.conf`;
  no system Apache or external network touched.

## Exact commands

```sh
# Build (from repo root; all outputs under w2/)
mkdir -p lab/frontier/cjose2shell/w2/evidence
./lab/frontier/cjose2shell/w2/build.sh > lab/frontier/cjose2shell/w2/evidence/build.out 2>&1

# Local key + config check
cd lab/frontier/cjose2shell/w2
openssl genrsa -out lab-rsa.pem 2048
/usr/sbin/apache2 -t -f "$PWD/apache.conf"

# gdb launch (Yama ptrace_scope prevents attach to an unrelated process, so gdb
# starts Apache as its child); pending breakpoints resolve on dlopen of the module
timeout 180 gdb -q -batch -x "$PWD/gdb.cmd" \
  --args /usr/sbin/apache2 -f "$PWD/apache.conf" -X > evidence/gdb-stdout.log 2>&1

# Three raw loopback POSTs (from another shell, while gdb is running)
./probe.py no_kid_oversized
./probe.py kid_rsa_oversized
./probe.py kid_rsa_valid
```

`build.sh` writes `pkgconfig/jansson.pc` and `pkgconfig/cjose.pc` under `w2/`,
sets `PKG_CONFIG_PATH` for `configure`, and builds both libraries from copies;
no tracked file was edited. `apache.conf` supplies `OIDCPrivateKeyFiles`
(`w2-rsa-kid#.../lab-rsa.pem`), `OIDCRedirectURI`, `OIDCCryptoPassphrase`,
issuer/authorization endpoint, and `AuthType openid-connect` on `/redirect_uri`.
`gdb.cmd` breaks on `oidc_handle_logout_backchannel`, `oidc_jwe_decrypt_impl`,
`cjose_jwe_decrypt`, `_cjose_jwe_decrypt_ek_aes_kw`, and `AES_unwrap_key`.

## Probe construction

`probe.py` uses the lab KEK `dfddb556b3b94eb2ef3d0f8d14b96085` and RFC 3394 AES
wrap (same routine as `w1/client.py`). Protected header:
`{"alg":"A128KW","enc":"A128CBC-HS256"}`, optionally with
`"kid":"w2-rsa-kid"`. Raw `encrypted_key` lengths: 56 bytes (oversized, wraps
48-byte plaintext) and 40 bytes (correct A128KW, wraps 32-byte CEK). The second
(base64url) segment is 75 chars for 56 raw bytes, 54 chars for 40 raw bytes.
Raw request/response bytes are preserved as `evidence/request-*.bin` and
`evidence/response-*.bin`; tokens in `evidence/token-*.txt`; hashes in
`evidence/SHA256SUMS`.

## Observed evidence

`evidence/gdb.log` (order of the three POSTs):

```
W2_BACKCHANNEL_HIT
W2_OIDC_JWE_DECRYPT_IMPL_REACHED                       # no_kid_oversized, 56 bytes
W2_BACKCHANNEL_HIT
W2_OIDC_JWE_DECRYPT_IMPL_REACHED                       # kid_rsa_oversized, 56 bytes
W2_CJOSE_JWE_DECRYPT_REACHED jwk_kty=1
W2_AES_KW_DECRYPT_REACHED raw_len=56 cek_len=0 jwk_kty=1
W2_BACKCHANNEL_HIT
W2_OIDC_JWE_DECRYPT_IMPL_REACHED                       # kid_rsa_valid, 40 bytes
W2_CJOSE_JWE_DECRYPT_REACHED jwk_kty=1
W2_AES_KW_DECRYPT_REACHED raw_len=40 cek_len=0 jwk_kty=1
```

`CJOSE_JWK_KTY_RSA = 1` (`cjose/include/cjose/jwk.h:32`), so the key passed to
cjose is RSA, not OCT. There is **no** `W2_AES_UNWRAP_KEY_REACHED` line:
`AES_unwrap_key()` was not called in any scenario. No ASan fault, no crash.

`evidence/apache_error.log`, exact downstream results (HTTP 400 in all three):

* no kid, 56 bytes — `oidc_jwt_parse failed: [src/jose.c:753: oidc_jwe_decrypt_impl]:
  encrypted JWT could not be decrypted with any of the 1 keys`
* kid, 56 bytes — `oidc_jwt_parse failed: [src/jose.c:727: oidc_jwe_decrypt_impl]:
  encrypted JWT could not be decrypted with kid w2-rsa-kid: invalid argument
  [file: jwe.c, function: _cjose_jwe_decrypt_ek_aes_kw, line: 577]`
* kid, 40 bytes (safe-length control) — same `invalid argument ... line: 577`;
  rejection is key type, not encrypted-key length.

Responses: `HTTP/1.1 400 Bad Request`, `Content-Length: 226`,
`Cache-Control: no-cache, no-store`, `Pragma: no-cache` (raw bytes in
`evidence/response-*.bin`).

## Why the key type is RSA (configuration blocker, no module patch applied)

`src/mod_auth_openidc.c:3181` passes `oidc_util_merge_symmetric_key(r->pool,
cfg->private_keys, NULL)` to `oidc_jwt_parse()`. That helper only copies
`cfg->private_keys`; `cfg->private_keys` is populated only by
`OIDCPrivateKeyFiles` (`src/config.c:879-905`), which parses PEM RSA/EC private
keys via `PEM_read_bio_PrivateKey()` (`src/jose.c:1475-1575`). The symmetric-key
directive `oidc_set_shared_keys` (`src/config.c:846-874`) feeds OAuth verify
keys, not `private_keys`. Therefore no stock configuration supplies an OCT KEK
to this unauthenticated POST path. The module source was **not** patched to
force one. With no `kid`, `oidc_jwe_decrypt_impl` additionally skips non-OCT
keys (`src/jose.c:703-757`, `oidc_alg2kty(A128KW)=OCT`); with a matching `kid`,
`cjose_jwe_decrypt()` is called but AES-KW rejects the RSA JWK before
`AES_unwrap_key()` (`src/jwe.c:574-579`).

A separate source-level follow-up (not measured here): `src/proto.c:1426-1434`
does create an OCT JWK from `provider->client_secret` and call
`oidc_jwt_parse()` before signature validation, but it needs a state cookie
from an earlier authorization request, so it is not this single unauthenticated
POST.

## Limitations

* No fixed-cjose control build was run: the exploit precondition (`AES_unwrap_key()`
  reached with an OCT JWK) is not met here, so a fixed-vs-vulnerable comparison
  would be identical and uninformative. The 40-byte safe-input control and the
  no-`kid`/matching-`kid` pair are the measured controls.
* gdb was attached by launching Apache as gdb's child because
  `/proc/sys/kernel/yama/ptrace_scope` blocks `gdb -p` for a separate process.
  Pending breakpoints resolved after the module's `dlopen` (verified by the
  `W2_*` lines).
* Only loopback HTTP POSTs were sent; no TLS, no external network, no other
  listener, no system Apache service changes, no commits or tracked-file edits.
  The private instance was terminated after evidence capture.

## W186 — id_token / OCT client_secret lane (23:18-23:22Z, measured)

No new binaries: the W184 module and vulnerable cjose build were reused.
`apache-idtoken.conf` adds `OIDCClientSecret w2-loopback-secret-0123456789`,
`OIDCResponseType id_token`, `OIDCResponseMode form_post` and a protected
`/private` location. The client secret yields a 16-byte OCT JWK (first 16
bytes of its SHA-256: `e6e411c2390f0130d75a4fe5b28e6601`); the lab wrap KEK
in `probe.py` does not match it, so OpenSSL rejects the unwrapped CEK after
the copy. Only the attacker-chosen write length is under test, as in a
deployment where the recipient KEK is secret.

Replay (loopback only, no system Apache):

```sh
cd lab/frontier/cjose2shell/w2
timeout 120 gdb -q -batch -x "$PWD/gdb-idtoken-abort.cmd" \
  --args /usr/sbin/apache2 -f "$PWD/apache-idtoken.conf" -X \
  > evidence/gdb-idtoken-oversized-stdout.log 2>&1   # separate shell
./probe-idtoken.py valid                              # correct-length control
./probe-idtoken.py oversized                          # 56-byte encrypted_key
```

Each probe first GETs `/private` with `Accept: text/html`, capturing the 302
`state` parameter and the encrypted `mod_auth_openidc_state_*` cookie, then
POSTs `state`, `id_token` and `response_mode=form_post` to `/redirect_uri`
with the same cookie and User-Agent. Tokens are those from `probe.py` with
raw encrypted_key length 56 or 40. After the oversized POST, a follow-up GET
`/private` drives the allocator that exposes the corruption.

Measured result: HTTP 400 for both POSTs (integrity failure after the wrap),
but gdb logs `W2I_PARSE_IDTOKEN_REACHED`,
`W2I_CJOSE_JWE_DECRYPT_REACHED jwk_kty=3` (OCT),
`W2I_AES_KW_DECRYPT_REACHED raw_len=56 cek_len=0 jwk_kty=3` and
`W2I_AES_UNWRAP_KEY_REACHED` (`evidence/gdb-idtoken-run3.log` and
`evidence/gdb-idtoken-crash-final.log`). The follow-up GET aborted the Apache
process with glibc `free(): invalid next size (fast)` in
`jsonp_free -> json_delete_string -> json_decref -> oidc_proto_state_destroy`
(`src/proto.c:797`); the full backtrace is in
`evidence/gdb-idtoken-crash-final.log`, raw message in
`evidence/idtoken-apache_error.log`. The 40-byte control reached
`W2I_AES_UNWRAP_KEY_REACHED` with `raw_len=40` and no abort
(`evidence/gdb-idtoken-abort.log`, which is the valid-control log despite
its filename). The first oversized run aborted a few seconds later on its
own follow-up request (`evidence/gdb-idtoken-stdout-run3.log` plus
`evidence/idtoken-oversized-run3-apache.txt`). Raw GET/POST bytes, tokens,
state cookies and hashes are under `evidence/` (`idtoken-SHA256SUMS`).

Two failed setup attempts are preserved, not erased: a GET without
`Accept: text/html` returned 401 (`evidence/idtoken-get-response-oversized.bin`
was overwritten by the successful run), and without `OIDCResponseMode
form_post` the module rejected the response as `fragment` vs `form_post`
before reaching `oidc_proto_parse_idtoken`.

Verdict: measured pre-signature reachability of the overflow inside a real
mod_auth_openidc consumer with a lab-configured OCT KEK and a matching state
cookie from an earlier loopback authorization request. Not deployed
reachability, no pointer/IP control, no benign marker, no r5. The witness
has not replayed this lane. Listener was 127.0.0.1:18443 only and was stopped
after capture; no 18443 listener or lab Apache remained.
