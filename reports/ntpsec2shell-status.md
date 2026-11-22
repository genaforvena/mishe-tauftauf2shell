# ntpsec2shell — status

Admitted 2026-11-22 ~21:2xZ under standing approval #6 as the 85th engine
route. Charter `.mishe-tauftauf/charters/ntpsec2shell.md` and seed wall
`.mishe-tauftauf/walls/ntpsec2shell.md` were created by frontier at W121; the
two-pane window (inner index 90, registry entry 91) already existed and was
adopted, not duplicated. Admission added the hy4-flash `max_parallel: 3` route
and the three units from the exact full-flag sync (pin
`0d686bbad55c849e88334da64efff9da88ad528a`, `written 9, removed 0` across all
three admitted targets). Pinned `doctor` and `check-omp-only.py` are GREEN.

- Claim: CVE-2026-121506, "Out-of-bounds Write in NTPsec", GitLab CNA
  2026-11-03, CWE-787, CVSS v3.1 7.4
  (`AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H`). An out-of-bounds read and write in
  NTS client extension parsing (`extens_client_recv`) in NTPsec before 1.2.5
  lets a remote attacker who can send NTP server-mode replies to an NTS client
  corrupt heap memory and crash ntpd. Affected 1.1.4 up to (excluding) 1.2.5;
  fix commit `0a36941e499d533dfbc3fb6b1fcd8c367679d719`. Sources and the fix
  patch are in `lab/frontier/ntpsec2shell/PROVENANCE.md`.
- Primitive: the vulnerable pin reads a declared `noncelen` and a second
  uint16 from the packet with no check against the extension length, then
  computes `plaintext = nonce+noncelen+CMAC_LENGTH` and advances the cursor by
  the compile-time `NONCE_LENGTH+CMAC_LENGTH`. The leftover `buf.left` is then
  passed as the decrypt output length to the pinned `AES_SIV_Decrypt()`, which
  writes through the out-of-range `plaintext` pointer. The fix rejects
  `noncelen+CMAC_LENGTH > length`, recomputes `outlen` from `noncelen` and
  advances by `noncelen+CMAC_LENGTH`.
- Pins: vulnerable tag `NTPsec_1_2_4` `a9e66af44c0be47e8e32a972b3f3fb7cea65f808`;
  fixed tag `NTPsec_1_2_5` `42b5703303c8c7e6513f3a119cfab670924dd7be`; fix
  `0a36941e…`. Full digests in `lab/frontier/ntpsec2shell/PIN_HASHES.txt`.
- Evidence (`bash lab/frontier/ntpsec2shell/harness/run.sh`, 8 PASS / 0 FAIL
  twice plus a clean `git archive f035109` replay, normalized SHA-256
  `1f04e12d2a9332d2cf9f0161c1a9155f40d8d6936b13b295934113ad7e164106`):
  crafted AEEF record with `noncelen=64` on the vulnerable pin gives ASan
  `heap-buffer-overflow`, `WRITE of size 40`, 8 bytes after a 128-byte region,
  frames `AES_SIV_Decrypt` (modeled) → `extens_client_recv` (verbatim pinned)
  → `stub_case`. Plain build reads back 16 chosen `0x41`/`0x5a` bytes at offset
  136. With the pinned real AES-SIV and a lab-chosen key, 16 chosen bytes
  `414243…50` land at offset 328 of a declared 104-byte datagram. Fixed pin
  rejects before the consumer; safe `noncelen=16` writes in-bounds on both pins.
- Grade: rung 1 (deterministic crafted record), rung 2 (unchecked length) and
  rung 3 (ASan OOB write) at verbatim-harness scope; rung 4 chosen bytes at a
  chosen offset with both a modeled consumer and the pinned real AES-SIV.
  Ceiling: the victim is an **NTS client ntpd receiving server-mode replies**,
  not a server. No ntpd process, NTP/UDP wire, NTS-KE handshake, disclosed
  `s2c` key, pointer control, function-pointer overwrite, marker, command or
  rung 5. The advisory's chained auth-bypass/time-setting claim is claim text.
- Cheapest next experiment: build vulnerable 1.2.4 ntpd with NTS enabled, run
  a plant-started loopback NTS-KE service and malicious NTP server, and replay
  the crafted AEEF record in a server-mode reply; 1.2.5, a well-formed reply
  and a non-NTS peer are controls. A second question is whether the 1.2.4
  NTS-KE OOB read discloses `s2c` bytes, which decides whether attacker-chosen
  decrypted content is realistic.
- Full stage: `reports/frontier-ntpsec2shell.md`.

No witness replay has been requested yet.
