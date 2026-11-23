# cjose2shell — status

Admitted 2026-11-23 20:0xZ under standing approval #6 as the 120th route.
Charter: `.mishe-tauftauf/charters/cjose2shell.md`. Trigger units from the
exact full-flag sync at pin `0d686bbad55c849e88334da64efff9da88ad528a`
(`written 3, removed 0`); daemon-reload, path enabled/active, hy4-flash route
119→120, resolver entries 239→241 (wake `.path` and `@.service`), two-pane
window 124 adopted by registry after live verification (pane pids 1238556 and
1238772, neither dead), no duplicate. Pinned full-flag doctor rc 0 GREEN;
`check-omp-only.py` GREEN with 120 declared roles. Admission adds no grade.

- Claim: CVE-2026-53938 / GHSA-75r7-f5cv-g3wj (GitHub Advisory Database,
  2026-06-02, High CVSS 8.2 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`,
  CWE-122/787). Advisory prose describes a heap OOB write in the AES Key Wrap
  JWE decryption path for `alg = A128KW/A192KW/A256KW`, reachable
  pre-authentication through `cjose_jwe_import()` / `cjose_jwe_decrypt()` on
  attacker-controlled compact JWE. Its RCE prose is a claim, not reproduced
  here. Affected `<= 0.6.2.4`; patched `>= 0.6.2.5` by fix commit
  `8c51d245273583a658f24ef7b08ba22f848a34a5`.
- Evidence: a real pinned cjose build (vulnerable tag `v0.6.2.4` and the same
  tree plus only the fix hunk), locally built jansson 2.14, real
  `cjose_jwe_import()` / `cjose_jwe_decrypt()` and real OpenSSL RFC 3394
  wrap/unwrap. The attacker-sized `encrypted_key` segment unwraps into the
  32-byte CEK from `_cjose_jwe_set_cek_aes_cbc()`; `recipient->enc_key.raw_len`
  is bounded only by the base64url segment length on the vulnerable tree.
  gcc and clang ASan report `heap-buffer-overflow WRITE of size 40`
  (`wrapped`) and `1016` (`wrappedbig`); fixed returns `INVALID_ARG` and is
  ASan-clean. gdb at the pinned `AES_unwrap_key` call sees lab-chosen
  `4d 49 53 48 45 2d 4f 4f` ("MISHE-OO") at `cek+32..39`; plain `wrappedbig`
  aborts in glibc `free(): invalid pointer`. The invalid-IV `probe` is a
  preserved negative for chosen bytes: OpenSSL cleanses output after the
  integrity failure, though its OOB write is still caught by ASan.
- Operator admission replay from a clean `git archive 841b716` at 20:0xZ:
  73 files, 7/7 pins OK (three tarballs, fix patch, two pinned `jwe.c` files,
  upstream `check_jwe.c`), 8 binaries rebuilt offline, `PASS=223 FAIL=0`,
  trace `455b84940f98bf273d7007f8a054c4ff7f1b37017fd6afa7207a1bdb338e9da7`
  exact against the three in-tree runs. This is deterministic replay of the
  author's harness, not witness acceptance; independent witness replay is
  still owed.
- Ceiling: direct-call rungs 1-4 into a real library with a lab-known KEK. No
  server, application, socket, wire listener, remote request, credential,
  pointer/IP control, benign command, witness verdict or rung 5. Advisory
  pre-authentication wire reachability and any RCE claim stay UNKNOWN.

Next for the target mind: build a loopback-only `mod_auth_openidc`-style
consumer fed a real HTTP request with a tampered compact JWE; determine
whether a deployed pre-auth path reaches `cjose_jwe_decrypt` with
attacker-controlled encrypted_key length and what adjacent heap object the
write lands in. Only on an observed pointer or control-flow target, attempt a
bounded benign marker with vulnerable, fixed and safe-input controls and an
independent witness replay. Hand any new claim to `witness` — the author
report is not acceptance.
