# Frontier brief: NTPsec — CVE-2026-121506 (ntpsec2shell)

Status W121 (2026-11-22): screened in and staged at rung 3 (ASan-confirmed
OOB write in a verbatim pinned function) plus rung 4 (chosen bytes at a chosen
offset, including through the pinned real AES-SIV consumer). Duplicate check
before provisioning: no prior `reports/frontier-*ntp*`, no NTPsec/ntpd window,
charter or mind on the tape; PHP-CGI's adjacent CVE-2026-129538 was rejected as
already owned by the `php2shell` mind (`docs/task.md`). The victim here is an
**NTS client** ntpd receiving server-mode replies, not an NTP server; keep that
ceiling honest at admission. The operator owns final admission; wake units and
full-flag sync stay with the person.

## 1. Verified ground truth

- Claim: CVE-2026-121506, "Out-of-bounds Write in NTPsec", GitLab CNA,
  published 2026-11-03. An out-of-bounds read and write in NTS client extension
  field parsing (`extens_client_recv`) in NTPsec before 1.2.5 lets a remote
  attacker who can send NTP server-mode replies to an NTS client corrupt heap
  memory and crash ntpd; CWE-787, CVSS v3.1 7.4
  (`AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H`). Affected 1.1.4 up to (excluding)
  1.2.5; upgrade to 1.2.5. Credit: OSS-Fuzz issue 393742176, analysis by Erica
  Windisch (Cyberdione Labs).
- Sources read (read-only provisioning, no external probe):
  `https://cveawg.mitre.org/api/cve/CVE-2026-121506`, the public fix commit and
  patch `https://gitlab.com/NTPsec/ntpsec/-/commit/0a36941e499d533dfbc3fb6b1fcd8c367679d719`,
  and raw pinned `ntpd/nts_extens.c`, `ntpd/nts.c`, `include/nts.h`,
  `libaes_siv/aes_siv.c` and `include/aes_siv.h` blobs.
- Pins: vulnerable tag `NTPsec_1_2_4` =
  `a9e66af44c0be47e8e32a972b3f3fb7cea65f808`; fixed tag `NTPsec_1_2_5` =
  `42b5703303c8c7e6513f3a119cfab670924dd7be`; fix commit
  `0a36941e499d533dfbc3fb6b1fcd8c367679d719` (authored 2025-05-01, "Add length
  checks to fix fuzzer 393742176 / Also fix nonce length checking").
- The advisory further claims that combining this write with the NTS-KE
  out-of-bounds read fixed in 1.2.4 can bypass NTS authentication and set the
  client's time. That is a **claim**, not a local observation. No key leak,
  auth bypass or time change was reproduced here.
- Access prerequisites: the target must be an NTS-enabled client, and the
  attacker must be able to send NTP server-mode replies that reach
  `extens_client_recv()`. A real AES-SIV decryption that yields chosen
  plaintext also needs the `s2c` key; the harness uses a lab-chosen key, not a
  disclosed one.

## 2. Source-bound mechanism and fix

In the vulnerable pin (`ntpd/nts_extens.c:403-427`), the NTS_AEEF branch reads
`noncelen` and a second uint16 from the packet, then computes:

```c
nonce = buf.next;
ciphertext = nonce+noncelen;
plaintext = ciphertext+CMAC_LENGTH;
outlen = buf.left-NONCE_LENGTH-CMAC_LENGTH;   /* NONCE_LENGTH is compile-time 16 */
ok = AES_SIV_Decrypt(wire_ctx, plaintext, &outlen, ...,
                     nonce, noncelen, ciphertext, outlen+CMAC_LENGTH,
                     pkt, adlength);
```

There is no check that the packet-declared `noncelen` fits the extension
length. A larger `noncelen` moves both the ciphertext and the decrypt output
past the received data; the cursor is then advanced by the constant
`NONCE_LENGTH+CMAC_LENGTH` instead of `noncelen+CMAC_LENGTH`, leaving stale
`buf.left`. The pinned `libaes_siv/aes_siv.c` `AES_SIV_Decrypt()` writes the
decrypted bytes through its `out` pointer, which is the computed `plaintext`.

Upstream fix `0a36941e` adds four checks/changes: reject `2*NTP_EX_U16_LNG >
length`, reject `noncelen+CMAC_LENGTH > length`, compute
`outlen = buf.left-noncelen-CMAC_LENGTH`, and advance by
`noncelen+CMAC_LENGTH`. Both pins' `extens_client_recv()` bodies and the fix
hunk are in `lab/frontier/ntpsec2shell/pins/`.

## 3. Measured evidence (this lab)

Everything lives in `lab/frontier/ntpsec2shell/`; harness `gen.py` copies
`extens_client_recv()` byte-for-byte from the pinned blob into `fn.inc`, and
the two buffer helpers from pinned `ntpd/nts.c`. Structs, counters and packet
construction are local stubs. `harness/run.sh` builds both pins with gcc,
ASan and a plain build, and links the pinned 1.2.4 `libaes_siv/aes_siv.c`
against OpenSSL 3.0.13. No sockets, no external systems.

- **ASan (exact-sized packet allocation):** crafted AEEF record with
  `noncelen=64` on the vulnerable pin gives `AddressSanitizer:
  heap-buffer-overflow`, `WRITE of size 40`, **8 bytes after a 128-byte
  region**, top frames `AES_SIV_Decrypt` (modeled consumer) →
  `extens_client_recv` (verbatim pinned function) → `stub_case`. The fixed pin
  rejects the same packet before reaching the consumer (`FN_RC=0`,
  `WRITE_OFF=-1`).
- **Chosen bytes (plain build, padded allocation so glibc metadata survives
  the modeled write):** the same crafted record yields 40 written bytes at
  offset 136, i.e. 8 past the declared 128-byte packet; the first 16 readback
  bytes are `AAAAAAAAAAAAAAAA` for fill `0x41` and `ZZZZZZZZZZZZZZZZ` for
  `0x5a`. A safe `noncelen=16` writes at offset 88, entirely inside the
  packet, on both pins.
- **Real pinned AES-SIV consumer:** with a 1024-byte receive buffer, a
  declared 104-byte datagram and a valid AES-SIV ciphertext placed at offset
  312, the vulnerable pinned function passes `plaintext = buf+328` to the real
  pinned decryptor; 16 chosen bytes `41 42 43 44 45 46 47 48 49 4a 4b 4c 4d
  4e 4f 50` are observed at that offset, 224 bytes past the declared
  datagram. The fixed pin leaves the same bytes as the unchanged ciphertext
  payload. Both pins return `false` afterwards because the vulnerable cursor
  advance leaves `buf.left=16`; only the write is claimed, not acceptance of
  the packet.
- `harness/run.sh`: **8 PASS / 0 FAIL** on two consecutive in-tree replays
  with byte-identical normalized PASS lines (SHA-256
  `1f04e12d2a9332d2cf9f0161c1a9155f40d8d6936b13b295934113ad7e164106`).
  Raw evidence: `lab/frontier/ntpsec2shell/evidence/`.

## 4. Rung-4 feasibility and honest ceiling

Rung 1 (deterministic crafted AEEF record), rung 2 (declared noncelen accepted
without a length check) and rung 3 (ASan-confirmed OOB write) are direct-call
facts on the vulnerable pin. Rung 4 is chosen bytes at a chosen offset, both
with a modeled decrypt consumer and with the pinned real AES-SIV implementation
using a lab-chosen key.

Ceiling: no ntpd process, no NTP/UDP wire, no NTS-KE handshake, no disclosed
key, no pointer control, no function-pointer overwrite, no benign marker
execution, no command and no rung 5. The advisory's auth-bypass/time-setting
chain is unverified. The ASan case uses a modeled consumer because the real
decryptor reads the out-of-range ciphertext before it writes; the real-crypto
case deliberately keeps the write inside the receive buffer so the chosen
plaintext can be read back. Neither is a live-daemon observation.

Tractability: high — two release pins, one small fix hunk, a plain C tree with
bundled crypto, and a short parser function. It outranks the parked
FRR/llama.cpp/Libreswan tail because the primitive is a write with a
packet-controlled offset and an exact upstream fix.

## 5. Cheapest next experiment to move up a rung

Build vulnerable 1.2.4 ntpd with NTS enabled, start an NTS-KE service and a
malicious NTP server on plant-started 127.0.0.1 sockets, and replay the crafted
AEEF record in a server-mode reply to the local client. ASan should report the
write inside `extens_client_recv()`; a plain build plus gdb at the
`AES_SIV_Decrypt()` call can read back chosen `plaintext` bytes in the live
process. A second bounded question is whether the 1.2.4 NTS-KE OOB read really
discloses `s2c` bytes, which decides whether attacker-chosen decrypted content
is realistic or only stale heap content. Fixed 1.2.5, a well-formed AEEF
reply and a non-NTS peer remain controls.

## 6. Candidates screened this wake

- Rejected as already owned: PHP-CGI CVE-2026-129538 (`php2shell` mind owns the
  adjacent lane and all its FastCGI/HTTP work), Mosquitto CVE-2026-110486
  (`mosquitto`), FreeSWITCH, rsyslog, Netatalk CVE-2026-62321 (`netatalk`),
  ClassiCube, Apache mod_proxy_html (`apache2shell`).
- Rejected on evidence/ceiling: X.Org CVE-2026-109093 (AV:L, authenticated,
  high-axis device), Corosync CVE-2026-133475 (previously screened;
  network-adjacent with high privileges), Danfoss CVE-2026-129713 (no source
  or fix bytes), fqterm CVE-2026-131875 (terminal client victim), ClamAV
  CVE-2026-76421 (file scanner, not a wire daemon), PJSIP GHSA-69m4/GHSA-x72w
  (non-default DTLS+small MTU or explicit L16 codec, no CVE/pin pair).
- FRRouting CVE-2026-129217, llama.cpp CVE-2026-118375 and Libreswan
  CVE-2026-94453 remain queued below this find, unchanged.
- Do not duplicate the admitted list in `walls/frontier.md`; NGINX/Node belong
  to other minds.
