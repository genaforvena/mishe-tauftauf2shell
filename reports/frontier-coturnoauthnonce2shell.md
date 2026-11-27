# Frontier brief: coturnoauthnonce2shell — pre-auth OAuth nonce stack overwrite

**Status: STAGED, awaiting admission.** Frontier stage commit is recorded in
`lab/frontier/coturnoauthnonce2shell/PROVENANCE.md` and on this wake's wall.
Live two-pane window 214 is registered on the inner tmux socket. No witness
verdict yet; no rung 5 claim.

## Verified ground truth

- Claim source: GHSA-74pg-rfh2-5qw5 / CVE-2026-43994, published 2026-05-24,
  https://github.com/coturn/coturn/security/advisories/GHSA-74pg-rfh2-5qw5.
  High, CWE-120. The advisory claims a stack buffer overflow in
  `decode_oauth_token_gcm()` with an attacker-supplied `uint16_t nonce_len`,
  reachable before AES-GCM authentication on a server in `--oauth` mode, and
  shows an ASan WRITE-990 from a live 4.9.0 instance on `86e5e727`.
- Affected: coturn `<= 4.9.0`; patched `4.10.0`. Exact fix merged as
  `46368b3e1ecda2175f8db8b05ece8bbdbf844cea`; the PR head SHA `1513d746`
  named in the advisory is not in the cloned master history. `46368b3e` is an
  ancestor of tag `4.10.0` (`f07064f9`), and the advisory's test commit
  `86e5e727` is an ancestor of the pinned vulnerable parent `6e8dd731`.
- Pinned bytes: vulnerable archive `6e8dd731` SHA-256 `d5152f86…`, fixed
  archive `46368b3e` SHA-256 `44df0803…`. Claim source is read-only
  provisioning; nothing off loopback was contacted by a probe.

## Source-bound mechanism

Pinned `client/ns_turn_msg.c:2349-2363`:

```c
const uint16_t nonce_len = nswap16(*((const uint16_t *)csnl));
dtoken->enc_block.nonce_length = nonce_len;
const size_t min_encoded_field_size =
    2 + 4 + 8 + nonce_len + 2 + OAUTH_GCM_TAG_SIZE + 1;
if (etoken->size < min_encoded_field_size) return false;
...
memcpy(dtoken->enc_block.nonce, nonce, nonce_len);
```

The size check validates the *source* token only; it never bounds
`nonce_len` by `OAUTH_MAX_NONCE_SIZE` (256). The destination is
`oauth_encrypted_block.nonce[256]` (`client/ns_turn_msg_defs.h:251-258`)
followed in the same struct by `key_length`, `mac_key[MAXSHASIZE]`,
`timestamp` and `lifetime`. The upstream fix inserts a seven-line
`nonce_len > OAUTH_MAX_NONCE_SIZE` guard before the copy.

The direct sink harness mirrors the upstream `FuzzOAuthToken.c` added by the
fix commit. `inputs/nonce-990.bin` is 1023 bytes: big-endian `0x03de`, 990
`0x41` nonce bytes, then the 31-byte encoded-field tail.

## Locally observed evidence

- Vulnerable ASan: rc 1, `stack-buffer-overflow`, `WRITE of size 990`,
  `decode_oauth_token_gcm` at `client/ns_turn_msg.c:2363` via
  `decode_oauth_token:2485`. First invalid byte is at offset 456, immediately
  after the 408-byte `dtoken` object in the harness frame — the adjacent
  stack object is underflowed.
- Fixed ASan, same input: rc 0, `nonce length too large: 990 > 256`,
  `DECODE_OK=0 NONCE_LEN=0`, no ASan report.
- Unprotected vulnerable plain build: rc 0 and
  `key_length=0x4141 mac_key0=0x41 timestamp=0x4141414141414141
  lifetime=0x41414141` — attacker-chosen `0x41` bytes at chosen offsets in
  the adjacent struct fields. Fixed plain build reports all-zero fields.
- nonce-256 and nonce-16 controls are clean on both builds. Both hit an
  unrelated OpenSSL error-path leak (present on vulnerable and fixed), so
  `run-all.sh` sets `ASAN_OPTIONS=detect_leaks=0` and preserves that as a
  negative.
- `bash run-all.sh`: **13 PASS / 0 FAIL**. Pins, hashes, commands and raw logs
  in `lab/frontier/coturnoauthnonce2shell/PROVENANCE.md`.

## Rung-4 feasibility and grade

**R1 ✓ / R2 ✓ / R3 ✓ ASan WRITE-990 / R4 LIMITED / R5 NOT CLAIMED.**

R4 is limited to chosen bytes in adjacent stack fields of an in-process
harness, not a demonstrated wire-driven control-flow hijack. The advisory
documents a network path (pre-auth STUN/TURN with `--oauth`, known kid, valid
NONCE, 20-byte arbitrary MESSAGE-INTEGRITY) and a Python PoC, but that path
was **not** replayed locally here; no live coturn process, loopback request,
saved-RIP value, branch target, marker or command was observed. Compiler
canaries and ASLR are unmeasured. The upgrade to a wire-reachable R4 is the
cheapest high-value next experiment: build the pinned vulnerable server with
ASan, start it on 127.0.0.1 with a test OAuth kid, replay a 401 NONCE challenge
then a crafted ALLOCATE, and compare fixed and safe-input controls.

Tractability is high: small one-file patch, exact pins, upstream direct sink
harness, four fast builds, deterministic 1023-byte input, and a documented
pre-auth network trigger. It outranks the other scout candidates (zchunk,
libiscsi, dr_flac, tcpreplay, alsa-lib) because the sink accepts an
attacker-chosen length and the advisory supplies the wire preconditions.

## Duplicate check and disposition

No coturn target or window existed in the plant's staged/admitted/screened
lists. This is a distinct sink, not a duplicate of any staged TURN/STUN or
OAuth target. Other scout shortlist candidates preserved as backups:
`libiscsiluns2shell` (4-byte heap write, `eff2822fd`), `zchunkrange2shell`
(CVE-2026-117556 sibling), `drflacseek2shell` (READ-11, header-only),
`tcpreplayservices2shell` (CVE-2026-102896), `alsalibname2shell`
(CVE-2026-90781), `c-icapserverencap2shell` (CVE-2026-136126),
`libstdc++filebuf2shell` (CVE-2026-125709, heavy build). None is staged.
