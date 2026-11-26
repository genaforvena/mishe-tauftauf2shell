# PROVENANCE — netrekcow2shell

Staged by frontier W261 (2026-11-26). All sources fetched read-only from
upstream GitHub/codeload; no external target contacted. All testing is
in-process with a protocol-shaped byte frame; no socket, listener or command.

## Claim and upstream pins

- CVE-2026-121969 (NVD): "netrek-client-cow through 3.3.3 contains a
  stack-based buffer overflow vulnerability in handleSMessage() in short.c
  that allows malicious servers to overflow a 100-byte stack buffer by sending
  oversized SP_S_MESSAGE packets." References include upstream issue #11 and
  fix commit `fb322e74abee3b0b76a9c5a31df6aab5585d3127` ("Fix SIGSEGVs",
  2026-11-04), plus a source pin at `3.3.3/short.c#L949`.
- `git ls-remote --tags`: `3.3.3 = 9395a07b0b25c036a3f706b188a38656adbde983`,
  `3.3.4 = 40616ada0630f9051575c03232dea5886ee93805`, HEAD
  `b37f06ead2eb062070d525b16ca255357d00bb1a`. The 3.3.4 release carries the
  fix; its extracted `handleSMessage` hunk is byte-identical to the fix commit.
- Advisory language ("malicious server", "man-in-the-middle", "crash the
  client") is a claim. The local result is an in-process harness, not a live
  wire session.

## SHA-256 pins

| Artifact | SHA-256 |
| --- | --- |
| `src/3.3.3.tgz` (codeload tag 3.3.3) | `27f36469f896bc0cca185803358f62688d086be1a6c02f3da15cef9f5fe62f64` |
| `src/3.3.4.tgz` (codeload tag 3.3.4, fixed) | `c7a4c08ccfd13dae4f6ca4b75834aa509e5d89f2309587a042133b0b5993de19` |
| `src/fb322e74abee3b0b76a9c5a31df6aab5585d3127.tgz` | `4d3a44f6a9d9fcba22bcbfb9df6b87d2fbad572b317b338a5c88d044efc60088` |
| `src/fb322e74.patch` | `7ccf699adf6233a316efb8cd7119d6df2a9c6bead7aae4a1348bc48d993bc8a4` |
| `src/poc.c` (driver, stubs only) | `2ded3cb55bfaa1ce2921cff4d8c0d1ed75c84ecd6ac53d83a5b3a7135cd3bd48` |
| `src/hunk_vuln.inc` (`#line 914 "short.c"` + 914-951) | `fd7a9abd4b33d350c9274d1080e8cb8e935841e203836d114bbb88c1252049de` |
| `src/hunk_fixed.inc` (`#line 916 "short.c"` + 916-965) | `216dc5454f5ab42d1a1e9f74bb87d292c9caaa04bc92b923c56d06cadec59303` |
| `src/mesg_struct.inc` (`#line 1170 "packets.h"` + 1170-1181) | `e706b004f20fa65c53fc2648c0a6c778815015092d54e1121770fce7c2598687` |
| `run-all.sh` (canonical replay wrapper) | `52078f004e10bc89c0faa96c8755287c7afd6adc92f1c123e7697b5ce1799288` |

The runner rechecks all nine pins on every invocation, asserts verbatim
function start lines 914/916, and asserts that the released 3.3.4 fixed hunk
equals the fix-commit hunk byte for byte. The extracted `#line` directives
make ASan attribute frames to the real source line numbers.

## Source-bound facts

- 3.3.3 `short.c:914-951`: `char buf[100]; char addrbuf[9];`; at `:949`,
  `sprintf(buf, "%-9s%s", addrbuf, &packet->mesg);`. No length check and no
  NUL guarantee for the packet body.
- `packets.h:1170-1181`: `struct mesg_s_spacket` has `unsigned char length`
  at offset 4 and `char mesg` at offset 5, followed by 78 declared padding
  bytes (79 including `mesg` through the 84-byte struct's end); `length` is
  attacker-supplied and can claim more.
- 3.3.4 `short.c:916-965`: computes
  `body_max = packet->length > offsetof(..., mesg) ? length - offsetof(...) : 0`,
  `n = strnlen(&packet->mesg, body_max)`, clamps `n` to `sizeof(body)-1`,
  copies into `char body[sizeof(buf)]`, and emits with
  `snprintf(buf, sizeof(buf), "%-9s%s", addrbuf, body)`. Also guards
  `m_recpt >= MAXPLAYER` in the MINDIV branch.

## Observed result (frontier author replay, 2026-11-26 10:41:46Z)

`./run-all.sh > evidence/run-all-console.log 2>&1`, rc 0,
**RESULT PASS=32 FAIL=0**. GCC and Clang, vulnerable tag 3.3.3:
`ERROR: AddressSanitizer: stack-buffer-overflow`, `WRITE of size 130`, frame
`handleSMessage ... short.c:949` past `buf[100]`. GCC's frame description is
`'buf' (line 916)` at `[80, 180)` with "Memory access at offset 180 overflows
this variable"; Clang's is `[32, 132)` with "offset 132 partially underflows
addrbuf". With `-fsanitize-recover=address` and
`ASAN_OPTIONS=halt_on_error=0` the same run prints `outlen=129`,
`b99=41 b100=4d b101=41 b102=52 b103=4b b128=42 b129=00`: server-chosen
`M`,`A`,`R`,`K` at stack offsets 100..103, i.e. past the 100-byte buffer.
This byte capture is in ASan's **poisoned redzone**, not a named adjacent
object. Released fixed tag 3.3.4 (GCC+Clang, ASan and plain) is clean and
prints `outlen=99` for the attack frame and `outlen=14` for the safe frame;
the vulnerable safe frame is also clean at `outlen=14`.

## Negatives and corrections preserved

- Plain builds with the distribution's default stack protector abort with
  `*** stack smashing detected ***` before the sink's output can be read.
  Plain harness builds therefore use `-fno-stack-protector`; the ASan builds
  do too, so all modes differ only by sanitizer/fixed macro.
- Unprotected plain vulnerable attack runs still fault (`rc=139`, SIGSEGV)
  and print no byte dump. Byte-level evidence comes only from the
  explicitly-labeled recoverable-ASan mode.
- Recoverable ASan emits a second report from the harness `strncpy` sink,
  which reads the poisoned redzone after the interceptor recovers; this is an
  artifact of byte capture, not a second vulnerability in the target.
- The fixed build emits `-Wformat-truncation` for `snprintf` (output 10..109
  bytes into 100); that is the intended clamp, not an ASan finding.
- Fixed ASan/plain `outlen=99` is the truncated string length; the vulnerable
  attack frame is `outlen=129`, i.e. 29 bytes past a 100-byte buffer plus NUL.
- No wire socket, pcap, live target, named adjacent object, pointer control,
  command execution or r5 was observed. Do not upgrade the grade on the
  advisory's exploitability prose.

## Independent witness replay (W262, 10:48Z)

The unmodified runner was replayed from a clean `git archive f0672f0d`
subtree with archived evidence logs and generated `.inc` files removed and
all three tarballs re-fetched fresh: rc 0, `RESULT PASS=32 FAIL=0` in 4.58 s.
All pins, start lines, controls and compiler observations held; verdict
ESTABLISHED AS LABELED with no grade change and NO r5. Detail:
`.mishe-tauftauf/artifacts/witness-w262-netrekcow2shell/detail.md`.
