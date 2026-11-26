# PROVENANCE — quickjsng2shell (W279, 2026-11-26)

All fetches were public provisioning reads; no external target was probed, no
socket was opened, and no command from the advisory's os-module claim was run.
Everything executed was local.

## Pins and exact bytes

- Vulnerable tag `v0.14.0` = `3c051980ab7e783dfbfb1c70c014ce5e05ecf24c`;
  fixed tag `v0.15.0` = `433941b99fb3c5e7f98b7ebd78727972bcf467ee`.
  Advisory metadata claims affected `<0.14.0` and "Patched versions: None";
  source verification below contradicts both labels, so pins are by tag.
- Codeload tarballs and SHA-256:
  `https://codeload.github.com/quickjs-ng/quickjs/tar.gz/refs/tags/v0.14.0`
  = `928e9406addd99eb8623348f2cfcd916eade9a263c60d42be79bc7aee4ee8453`;
  `https://codeload.github.com/quickjs-ng/quickjs/tar.gz/refs/tags/v0.15.0`
  = `d65f951fa9d347a912a53ec2c151bd0ac79bf73d445788e67670ca1b894c67c4`.
- Verbatim `quickjs.c` SHA-256: v0.14.0
  `0dc62d8f9a2ed0e6f19fba948a1c54ee09c8d5c74545a814918716da89ccc35f`;
  v0.15.0
  `8bea2955bca8cfa5b8fe621fe162642244be2e640d6edd20ddcbe8482f4e5307`.
  Extracting `set_array_length()` as one function from each pin gives a diff of
  exactly **one added line**.
- Fix commit `da49a37041e78ba7148b24bf6500c4c18c8ecbb0` ("Addresses an
  incomplete fix from 1b0b660", 2026-05-11): patch URL
  `https://github.com/quickjs-ng/quickjs/commit/da49a37041e78ba7148b24bf6500c4c18c8ecbb0.patch`,
  SHA-256 `a19b577e7ba33f2ab231104a540b1c480e726bd51a5e2c7b54f1f7d94cf5b38d`.
  It adds `p->u.array.u.values[i] = JS_UNDEFINED;` after the `JS_FreeValue` in
  `set_array_length()` plus a six-line regression test.
- Advisory `https://github.com/quickjs-ng/quickjs/security/advisories/GHSA-r6vf-p8wr-4vg9`
  fetched 200; saved HTML SHA-256
  `8ce1c1372335f9c8f3b1462fa36ca88422dfca5b9a966e9ccbab92fa9db43561`.
  Advisory PoC `https://github.com/user-attachments/files/27544679/poc.js`
  SHA-256 `9b3ddd233a9298af8a5424b61dc89562d052a2d6742fff3eb726a742a0a12009`,
  byte-identical to the test added by the fix commit. Upstream ASan trace
  `https://github.com/user-attachments/files/27544678/asan.out.txt` SHA-256
  `23483850140760f3515b5ce587b3796fd314e91eb716f857f83dcafd2d6a773e`.
- Local file SHA-256: `run-all.sh`
  `f6e6c59f01b95073ed9d5b8521abfa162f3eb9efcd9e691d2088cbbb652cab59`,
  `verify.sh` `967c1f7d467d8dec7ebd9513a6ab42e3cd98b104b1f425f0eb2eda6c6a37706b`,
  `harness/safe.js` `a52394033893772a51bc5cdcfff020b30d06cda787640f2e5962a4f9b6922aec`,
  console `evidence-run-console.log`
  `55acc3aa1c4a707d752f96f792a8ce12fafc38d9e68efd3c1a14b698ca99ef61`.

## Reproduce

Refetch the two tarballs, PoC, patch and advisory HTML to `src/`; check hashes;
then from `lab/frontier/quickjsng2shell/`:

```
sh ./run-all.sh | tee evidence-run-console.log
sh ./verify.sh | tee -a evidence-run-console.log
```

`run-all.sh` builds the ordinary `qjs` CLI from unmodified pinned sources
(plus each tag's own generated `gen/repl.c` and `gen/standalone.c`) with GCC
13.3 `-fsanitize=address`, then runs the exact upstream PoC and a safe control.
`verify.sh` rechecks the saved evidence logs. At W279: `RESULT PASS=28 FAIL=0`
from `run-all.sh` and `RESULT PASS=11 FAIL=0` from `verify.sh`.

## Inputs and observed bytes

- Upstream six-line PoC: shrink a five-object fast array to length 2, regrow
  to 5, push a new object, read `arr[3]` with `JSON.stringify`.
- v0.14.0: GCC ASan `heap-use-after-free`, `READ of size 4`, frame
  `js_dup build/vuln/quickjs.c:1546` via
  `js_get_fast_array_element build/vuln/quickjs.c:9478`; address 0 bytes inside
  a 72-byte freed region; rc 1.
- v0.15.0: same script prints `undefined`, rc 0, no ASan report. Safe control
  (shrink to 2 and read only live slots) prints `2` / `[1,2]` on both pins,
  no ASan report.

## Preserved negatives and caveats

- No CVE; OSV lookup for this GHSA returned HTTP 404 in the read-only scout.
  Advisory metadata's affected/patched fields are stale; tag bytes are
  authoritative here.
- The advisory claims command execution when the `os` module is present;
  no os-module code, command or function-pointer control was used or observed.
- The stale upstream ASan trace uses a different GC-flavoured PoC
  (`poc_gc.js`) than the saved `poc.js`; this lab's trace is its own observation
  from the exact upstream regression test.
- Rung 3 only: no chosen-byte readback at chosen offsets, no pointer steering,
  no wire consumer, no command, no r5. Only GCC 13.3 was built; Clang was not.
- This is quickjs-ng, a distinct project from the already-staged
  bellard/quickjs `quickjsbcode2shell` lane.
