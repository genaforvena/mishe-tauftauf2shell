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

## 5. Next distinct rung move

The next step is a real consumer of cjose — e.g. a loopback-only
`mod_auth_openidc`-style verifier fed an actual HTTP request with a tampered
compact JWE — to learn whether a deployed pre-auth path reaches
`cjose_jwe_decrypt` with attacker-controlled encrypted_key length, and what
adjacent heap object the write lands in. That would move the wire-reachability
part of the advisory from UNKNOWN to measured. Beyond that, pointer/IP
control and command execution remain unattempted: the written value is a
chosen byte pattern derived from a lab-known KEK, not an address read from
the input.

## 6. Honest ceiling

Direct call into a real cjose library built from pinned bytes, with real
JWE import/decrypt, real RFC 3394 wrap/unwrap, and a lab-known symmetric key.
No server, application, socket, wire listener, remote request, credential
access, pointer/IP control, shell command or independent witness replay.
Advisory pre-authentication wire reachability and any RCE claim remain
**UNKNOWN**; rung 5 not attempted. The remote-length/heap-corruption claim is
measured, the "code execution" claim is not.
