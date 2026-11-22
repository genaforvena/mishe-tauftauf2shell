# BACnet/SC frontier lab — provenance

All work 2026-11-22, loopback/offline only. No external probe traffic.

## Pins

- Vulnerable: `https://github.com/bacnet-stack/bacnet-stack` at
  `1068250f197c0cc78b6357374d8be5df7d94b3cc` (2026-06-19,
  "bsc: reject short proprietary option headers (#1396)"), checkout in `src/`.
- Fixed: master merge of PR #1435,
  `37b081d0ebb2b92ca5297a5073850a467fa0e9c9` (2026-07-22,
  "fix: handle incomplete option list when 'More Options Follow' flag is set"),
  checked out in `src-fixed/` via `git worktree add`.
- Both SHAs recorded in `pins/PINS.txt`; fix diff in `pins/fix-97692.patch`
  (sha256 `ca3181b0d96df5ec385b9ea2f5f3358fd5d9ccce07f2d30ca5cee8904a5041d3`).
- Advisory: GHSA-gr74-333w-7wg8 / CVE-2026-97692, published 2026-10-04;
  public PoC (Dockerfile + poc.c) embedded in that advisory. OSV record
  `https://osv.dev/vulnerability/CVE-2026-97692`.

## Harnesses

- `harness/poc.c` — advisory PoC reproduced verbatim against the real
  `bvlc_sc_decode_message`, cases 1/2/3 selected by argv[1]. sha256
  `38cbe4b49d75be6ef8114f5c8480c09cf812ac711c648f06d6f87a6996660044`.
- `harness/poc_global.c` — server-shaped variant: file-static decode message
  and persistent RX buffer; chosen vendor/type bytes in the trailing chain;
  argv[1] bounds the chain (default 248). `-DDUMP` dumps `g_dm` before/after.
  sha256 `dc97401f1b8d437eb5c9cc72969ec6c0b741b2f7496594a3656d9b0382952acb`.

Build (vulnerable, from repo root of this lab dir):

```
clang -fsanitize=address,undefined -fno-sanitize-recover=undefined -g -O1 \
  -I src/src harness/poc.c src/src/bacnet/datalink/bsc/bvlc-sc.c \
  $(ls src/src/bacnet/*.c) src/src/bacnet/basic/sys/days.c -o harness/poc-vuln
```

Identical command with `src-fixed/` in place of `src/` builds the control.
The global harness builds the same way with `-DDUMP` for the plain readback.

## Evidence

- `out-vuln/case{1,2,3}.log` — three vendor-PoC conditions on 1068250f.
- `out-global/asan-full.log` — server-shaped ASan global-buffer-overflow.
- `out-global/plain-bounded.log` — plain byte dump, chosen `41 42 43` at
  offsets 304/344/384/424 past `dest_options[4]`.
- `out-fixed/` — all four controls on 37b081d0e.
- `evidence/norm-*` — normalized copies (addresses, PIDs and absolute paths
  replaced; lines sorted). `EVIDENCE_HASHES.txt` lists their sha256 values.

No live daemon was started and no wire packet was sent by this investigation;
the advisory's source-cited pre-auth server reach remains a claim, not a local
measurement. See `reports/frontier-bacnet2shell.md` for the rung assessment.
