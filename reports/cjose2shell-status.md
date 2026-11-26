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
  author's harness, not witness acceptance; scoped witness verdicts are now
  recorded below.
- Ceiling at admission: direct-call rungs 1-4 into a real library with a
  lab-known KEK. No server, application, socket, wire listener, remote
  request, credential, pointer/IP control, benign command, witness verdict or
  rung 5. Advisory pre-authentication wire reachability and any RCE claim
  stay UNKNOWN.
- Ceiling after W194 (witness #3566): the earlier graded scopes (direct-call
  rungs 1-4 and the synthetic-consumer rungs 1-3 plus byte-control mechanics)
  are unchanged; W194 adds one more scoped verdict. The W188 groomed
  direct-call function-pointer limb is **ESTABLISHED AS LABELED**. From a
  clean `git archive 8c717a2` replayed to `/tmp/w196-cjose`, the witness
  checked 7/7 pins, `sh replay-w188.sh` → `REPLAY_W188_OK`, `PASS=223 FAIL=0`
  and trace
  `455b84940f98bf273d7007f8a054c4ff7f1b37017fd6afa7207a1bdb338e9da7` exact;
  the vulnerable leg gave `GROOM_OK=1`, `CEK_LEN_AFTER=768`,
  `JWK_FNS_NOW==FAKE_FNS`, `BENIGN_MARKER_EXECUTED` and `MARKER_CALLED=1`,
  while the vulnerable fptrsafe and both fixed controls stayed at 0, with
  10/10 fresh vulnerable repeats and 0/5 fixed. A throwaway second marker
  fired for a different chosen fns pointer, showing the call followed the
  chosen value. Source-bound to vulnerable `jwe.c:566` unwrapping into
  `jwe->cek` without a length check, the sole fixed-tree guard at
  `jwe.c:594-602`, and `jwk.c:194` calling `jwk->fns->free_func(jwk)`. Ceiling:
  lab-known absolute address, groomed direct-call process, benign marker via
  real `cjose_jwk_release()`, no wire path, no ASLR defeat, no command and NO
  r5; W189's no-wire negative stands. W186/W187 stay separate author-only
  offers. Full evidence: `lab/frontier/cjose2shell/PROVENANCE.md` § W188 and
  W194, `reports/frontier-cjose2shell.md` § 5.

## 2026-11-26 01:27Z — W226 closes research at the documented ceiling

- Stopped the `--again 300s` chain. Grade unchanged: rungs 1-4 at labeled
  scopes (#3019, #3020, #3079, W188 #3566); no wire-derived address, ASLR
  defeat, command, deployed pre-auth verdict or r5. Advisory RCE claim stays
  UNKNOWN.
- Witness verdict UNKNOWN on queued offers #3925 and #4194. The witness wall's
  newest wake (01:17Z) is W236 (libxml2); leptonica #4625 and pgpool W9 #4634
  are ahead of cjose. Addressed replies wake this role directly and verdicts
  get folded into the reports, so retiring the timer loses no offer.
- All charter lanes closed by measurement: W212/W213/W215/W219/W220 bind the
  real pre-auth bearer lane (chosen bytes reach live objects, header type
  guard fails closed, KEK config-derived); W188/W203 need build-known
  addresses; W189/W190/W195-W197/W217/W218 exhaust adjacency and allocator
  routes without a wire-derived address.
- Fresh author receipt: `sh lab/frontier/cjose2shell/harness/check.sh` →
  `PASS=223 FAIL=0`, trace hash exact. Not witness acceptance. Reopen only on
  a widening witness verdict, a call/branch or marker at a wire-derived
  address in the real process, or a new loopback consumer changing lane bounds.
