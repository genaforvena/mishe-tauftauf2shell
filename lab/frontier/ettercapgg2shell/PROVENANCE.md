# ettercapgg2shell — provisioning provenance

All fetches were read-only public provisioning. Runtime uses one local process,
a command-line `u_int32` and local files: no packet capture, socket, listener,
TCP 8074 session, external system or network target is contacted at run time.

## Advisory and tags

- GHSA-vrjv-f8gv-2h35 (Ettercap/ettercap, published 2026-11-06):
  https://github.com/Ettercap/ettercap/security/advisories/GHSA-vrjv-f8gv-2h35
  — `gg_get_version()` in `src/dissectors/ec_gg.c` composes up to 44 bytes into
  the dissector's 30-byte heap `tbuf3` with `sprintf`/`strcat`. Affected
  `<= 0.8.4.1`, patched `0.8.5.1`. CVSS 3.1 8.1,
  `AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`, CWE-131/CWE-787.
- CVE-2026-125401 is listed in the advisory. RCE/exploitability framing is a
  claim; no command execution is observed here.
- Fix proposed in PR #1330 (branch `security/dream-2026-hardening`), patch
  head commit `a8c1a5085791b38c234be0e4129302fdc36964e0`. The advisory credits
  validation against master commit `3548c10c30c730e92035f793a1b6ff31e028acc8`.
- `git ls-remote --tags https://github.com/Ettercap/ettercap.git` verified
  `v0.8.4.1 = 0dc8409779f3a09cbfff4434b9a4d7b33480d88d` (lightweight) and
  `v0.8.5.1^{} = 832524f3c4c215f1007fe9f190dbf052ee965b55` (annotated).
  Both tarballs below are codeload archives fetched **by those commit SHAs**.

## SHA-256 pins (verified 2026-11-26)

| artifact | SHA-256 |
| --- | --- |
| `src/v0.8.4.1.tar.gz` (codeload by commit SHA) | `f8fbcf0b0c7091559f1c772f742224c748259dda19cadc5225877cebaef28fff` |
| `src/v0.8.5.1.tar.gz` (codeload by commit SHA) | `f63182623b5ca85754c87c4bf5da681836fbc741c56c017818d8c8fec228c273` |
| `src/fix-1330.patch` (PR #1330 patch) | `4ab380d9fa46bde9052542f76e1fd70c13889da63bda1729fbe965916d58ee5c` |
| verbatim vulnerable body (`ec_gg.c:599..678` + `#line`) | `bef7c986fe4beb24df4a99ba13040cf46246cbb653439f22a160d8710def0cbf` |
| verbatim fixed body (`ec_gg.c:631..717` + `#line`) | `9ec393ab324ed43cd6a3a7e68f761139a84400abc00fc8e49dcca4f48dae3508` |
| `poc.c` | `f839ae7183a2494cbdafcc56e1ee1f01b81cbf82674c61eeadcce5f50fb65e67` |
| `run-all.sh` (canonical runner) | `35c3f7d532a62b107f806d7b126e4f76bead860d949ce7b57217e22f458958c4` |

The runner rechecks all four source/driver pins, re-extracts both trees from
the pinned archives, asserts both function start lines (599 / 631), checks the
generated body hashes, and asserts the marker strings in the fixed hunk before
building. The generated `.inc` files carry `#line 599`/`#line 631` naming
`src/dissectors/ec_gg.c`, so sanitizer frames use verbatim upstream line numbers.

## Pinned source facts

- Vulnerable `src/dissectors/ec_gg.c:356`: `SAFE_CALLOC(tbuf3, 30, sizeof(char));`
  in `dissector_gg()`. The same function casts the attacker-supplied TCP
  payload to `gg_login50_hdr` / `gg_login60_hdr` / `gg_login70_hdr` /
  `gg_status50_hdr` and passes `->version` to `gg_get_version(...)` before the
  per-message `if (gg->len < offset)` guards.
- Vulnerable `gg_get_version` (`:599..678`) writes with `strcpy`/`sprintf`
  straight into `str`, then `strcat(str," + has audio")` at `:673` and
  `strcat(str," + eraomnix")` at `:676` under two flag tests.
- Fixed `gg_get_version` (`:631..717`) composes into a local `char buf[128]`
  and copies with `snprintf(str, size, "%s", buf)` at `:715`. The fixed
  dissector allocates `SAFE_CALLOC(tbuf3, GG_TBUF3_SIZE, ...)` with
  `GG_TBUF3_SIZE 64` at `:171`, and passes that size to the helper.
- The only harness adaptation is a typedef matching verbatim upstream
  `include/ec_stdint.h:39` (`typedef uint32_t u_int32;`). The extracted
  function bodies are byte-for-byte from the pinned tags.

## Observed result

`run-all.sh` at the pinned hash: **RESULT PASS=25 FAIL=0, rc 0**, console
`evidence/run-all-console.log`. Vulnerable GCC+Clang ASan on version
`0x44000042`: `ERROR: AddressSanitizer: heap-buffer-overflow`,
`WRITE of size 13`, `0 bytes after 30-byte region`, frame
`#1 gg_get_version src/dissectors/ec_gg.c:673` (the first `strcat`), allocation
from `poc.c:35`. The composed string is
`unknown (0x44000042) + has audio + eraomnix` = 43 chars + NUL = 44 bytes.
Both compilers' fixed-tag ASan and plain runs accept the attack version but
truncate output to 29 chars with the same 30-byte caller buffer; safe version
`0x0000002a` ("7.7") is clean on both tags. Plain vulnerable builds show the
attacker-chosen first hex digit `0x34` at offset 11 (in bounds) and the fixed
suffix bytes `0x69` at offset 30 and `0x78` at offset 42 (past the 30-byte
allocation).

Plain builds emit with `write(2)` and do not `free()`: the 14-byte overflow
corrupts the following chunk's size field, so `printf`/`free` abort with
`malloc(): corrupted top size` before the bytes can be read back. This is a
harness observation aid only; ASan builds free normally and abort inside the
sink on the attack input.

## Negatives and dead ends preserved


- Initial compile failed with `unknown type name 'u_int32'`; added the
  upstream-equivalent typedef in `poc.c` and re-pinned it. Function bodies
  unchanged.
- First plain driver used `printf` and `free`; the attack run aborted at
  `malloc(): corrupted top size` before emitting the snapshot. Snapshot is now
  built before output and emitted with `write(2)`.
- First readback expected `b1e`/`b2a` (hex labels) while the driver printed
  decimal offsets, and expected zeros at offsets 40..43 where the safe build
  legitimately shows allocator metadata (`b40=41 b41=0d b42=02`). Checks now
  use decimal offsets 11/30/42 for the attack and 30/35 for the safe control.
- Chosen hex digits of `version` always land at offsets 11..18 via
  `"unknown (0x%X)"`; the bytes that cross offset 30 are fixed suffix strings.
  Attacker control is over overflow *length* (flag bits and switch case), not
  over the overflowing bytes. No claimed chosen-byte adjacent object.
- No real `dissector_gg`, pcap, TCP 8074 wire, pointer control, command
  execution or r5 is claimed. Advisory impact prose remains a claim.
- One provisioning `curl` printed an HTTP 429 before a successful retry; every
  pinned artifact was then verified by SHA-256 and extracted successfully.

## Replay receipt

Author clean-archive replay of the unmodified runner from `git archive
30eb2847` into `.mishe-tauftauf/replays/ettercapgg2shell-w260/` reproduced
`RESULT PASS=25 FAIL=0`, rc 0 (console `replay-console.log`, finished
09:54:46Z), with runner sha256 `35c3f7d5…` unchanged and the same
`ec_gg.c:673` ASan frame. The first replay attempt from `9f1ae4bc` correctly
failed with `PIN_FAIL fix-pr1330` because the pinned patch had not been
tracked; `30eb2847` added it. This is an author-side replay, not independent
witness acceptance.
