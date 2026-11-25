# W18 — shipped 3.21e release-label check (source-bound, author replay)

Question: the pinned parent `42f586d7` is a development commit. Does the
no-size TERM getter and the adjacent-field layout that W1–W16 measured also
exist in the **shipped 3.21e release** named by the advisory's affected range
(3.20b–3.21e)?

One command from the repository root:

```
bash lab/frontier/synchronet2shell/release-label/run-release321e.sh
```

The script provisions four raw files from the GitHub mirror at the exact
commit the mirror's `sbbs321e` lightweight tag names
(`d2a6dcb27169796c3931f81c22b90d656d32bd97`), pins each file's SHA-256,
asserts the release markers `VERSION "3.21"` / `REVISION 'e'`, asserts
`TELNET_TERM_MAXLEN 40` (`terminal[41]`), and compares byte-for-byte the
getter-plus-clamp block and the adjacent `sbbs_t` field block against the
already-pinned parent copies under `lab/frontier/synchronet2shell/pins/`.
Live 2026-11-25T03:49:38Z: **11 PASS / 0 FAIL**, rc 0. Raw
`evidence/evidence.log` sha256
`6a6bf46f8a9fd3278c95f58ffb093ae51b31668027d9c01887f589bd2562300d`
(has the volatile `run` timestamp on line 1); with that line removed,
normalized sha256
`bb9067cf9bed5859e016f83175d8de91b2e1502a5a3df816e04cdbe73a3fbda9`.

Pinned release files (sha256, checked by the script):

- `answer.cpp` `307c39d4ec34270cf654fb144b5c67e277777cb71ced1ab1e485b7f84187fc33`
- `sbbsdefs.h` `22678cfed69588aea0f61ffa7a3a819e275dd5a685015bca4318b01a7c305ded`
- `sbbs.h` `ec26de45881d0d5dd8664b30fbd1c21e2d426d4609b6427aabada7210ea94655`
- `telnet.h` `a07664551c62620248025e8d0398a66080d6928cf2d7f6b5af08f7b7dbd9252d`

Limits: source-bound confirmation of the affected-release claim only. This
lane starts no build, no SSH service, no wire session, and measures no new
runtime bytes. It does not establish that 3.20b or any other release in the
advisory range is affected, does not change the rung, and is not an
independent witness verdict. Both wrong observations from this wake are kept
in `evidence/negatives.txt`.
