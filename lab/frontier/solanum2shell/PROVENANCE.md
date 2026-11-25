# solanum2shell staging provenance (2026-11-25)

## Provisioning (read-only public sources)

- Advisory: https://osv.dev/v1/vulns/CVE-2026-121603 (OSV API read
  2026-11-25T12:39Z), https://api.github.com/advisories/GHSA-6cq2-4j8w-7hvj ,
  https://github.com/advisories/GHSA-6cq2-4j8w-7hvj .
- Fix commit API read: https://api.github.com/repos/solanum-ircd/solanum/commits/2ea1382e4262b212a91034258c466f0f6754cd61
  message "KILL: Fix crash vulnerability due to missing reason length check
  (#550)", parent `7bc7e34c04711247b932666e19ae900cba884540`, 1 file
  `modules/core/m_kill.c`, +4/-0.
- Full source fetch via raw.githubusercontent.com at parent and fix commit;
  `git clone` of upstream into `upstream/` (45 MB) only to read constants.
- Constants verified in `upstream/include/ircd_defs.h`: KILLLEN 200 (:71),
  BUFSIZE 512 (:78). `LOCAL_COPY` verified in
  `upstream/include/stdinc.h:52` (strdupa).

## Pins (sha256, also in pins/SHA256SUMS)

```
f4af269d4c00efc07b54bbcec0526084d5d381277160bdb9956cd326bb302e5c  pins/m_kill.vuln.c      (parent 7bc7e34, 307 lines)
b1408e513f39e80c969513982a04522c6c182ad5d2ae37041ff1bc92ffeecd8d  pins/m_kill.fixed.c     (fix 2ea1382, 311 lines)
```

Function ranges: `ms_kill()` vulnerable `:170-280`, fixed `:170-284`;
store vulnerable `:277`, fixed `:281`. Fix hunk at fixed `:200-203`.

## Harness and exact evidence

`harness/extract-pins.sh` regenerates `pinned_vuln.h` / `pinned_fixed.h`
from the pins with `awk` and prints their sha256. `harness/run-all.sh`
checks pin hashes, byte-identical extraction, builds four binaries and
runs the controls; `evidence/` holds raw output.

- `evidence/vuln-gcc-asan-510.out`: `ERROR: AddressSanitizer:
  global-buffer-overflow`, `WRITE of size 533`, `0 bytes after global
  variable 'buf' ... of size 512`, stack `vsprintf` ← `sprintf` ← `ms_kill
  pinned_vuln.h:108` (= upstream `:277`) ← `main`.
- `evidence/vuln-clang-asan-510.out`: same WRITE at reason 510; both
  compilers also report at reason 700.
- `evidence/vuln-gcc-asan-safe.out`: reason 480 → `clean reason_len=480`,
  `buf_len` 502, no sanitizer report.
- `evidence/fixed-gcc-asan-510.out` / `-700.out`: `clean`, no report; the
  four-line truncation bounds reason to KILLLEN 200.
- `evidence/plain-510.out`: `reason_len=510 buf_len=532`,
  `oob=-SOLANUM-OOB-MISHE-)`: file/wire-chosen bytes visible past `buf+512`.
- `evidence/plain-480.out`: `buf_len=502`, no chosen pattern past the end.
- `RESULT 18 PASS / 0 FAIL` (2026-11-25T12:39:53Z).

## Negative results / limits preserved

- First harness run was 4 PASS / 14 FAIL: an earlier edit dropped the stub
  declarations for `find_person`, `form_str`, `L_KILL`, etc. Repaired by
  restoring them in `prelude.h`; all checks then passed. The failure was
  harness wiring, not a candidate disqualifier.
- Plain-readback assertion initially expected a pattern prefix at `buf+512`;
  the observed first byte is `'-'` because the reason begins at `buf+21`
  and 512-21 = 491, 491 mod 18 = 5 in the repeating marker. Assertion was
  corrected to the observed bytes, not the other way around.
- No real ircd build or linked-server wire test was attempted. ASan places
  a redzone after `buf`, so the chosen-byte readback is plain-build only.
- No pointer target, function-pointer adjacency, controlled RIP, command
  execution or R5 evidence. No external system probed; loopback only where
  applicable (none used).
