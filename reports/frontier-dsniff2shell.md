# frontier brief — dsniff2shell (CVE-2026-134753)

## Ground truth

- Claim: dsniff through 2.5a2 lets an unauthenticated sender of a UDP datagram
  to port 2001 drive `decode_sniffer()` past its global `obuf[4096]`; the packet
  controls the decoded bytes and their length. The reporter also claims a live
  single-packet crash on loopback with an unmodified compiled binary.
- Sources (read-only): VulnCheck advisory 2026-11-22 (CVE-2026-134753,
  CWE-191 -> CWE-787, CVSS 4.0 8.3
  `AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:H`), hackerschoice/dsniff#7
  (open, 2026-11-22, Umut Sevinç), upstream v2.5a2 `decode_sniffer.c` and
  `trigger.c`.
- Affected: dsniff <= 2.5a2, including the pinned tag. No upstream fix or
  patched release identified; issue is open.
- Primitive claimed: effectively unbounded write of attacker-chosen decoded
  bytes past a 4096-byte global. The issue calls it write-what-where; source
  review shows the destination is fixed at `obuf + strlen(obuf)`, so that
  phrase overstates it.

## Source-bound mechanism

At pinned `decode_sniffer.c:45`: `snprintf(obuf, olen, "%s [", &buf[32])`
truncates at `olen-1` when the packet's base64 string is long enough; then
`len = strlen(obuf)` saturates at 4095 and `olen - len - 3 == -2`. The signed
expression converts to a near-`SIZE_MAX` `size_t targsize` at the
`base64_pton(&buf[32], &obuf[len], ...)` call (line 47), disabling that
function's `tarindex >= targsize` bound (`base64.c:164` and neighbours). The
decoder then writes base64-decoded packet bytes starting at `obuf[4095]`, and
`obuf[len + i] = '\0'` writes still farther. Opcode 260 and `buf[0] == 5`
select this path; `strtok(&buf[32], "\r\n")` stops at CR/LF, so the payload
must avoid them. `trigger.c` supplies the real `static char obuf[4096]` and
dispatches decoders for UDP/2001.

The reporter's suggested fix clamps the remaining count at zero and handles a
negative `base64_pton` return; that is the local fixed control here, not a
vendor patch.

## Local experiment

`lab/frontier/dsniff2shell/` pins the v2.5a2 tarball (sha256
`23ada927…1610e3b4`) and compiles the **unmodified** upstream
`decode_sniffer.c` and `base64.c` into four harness builds (vulnerable/fixed,
ASan/guarded). The crafted record is the only input; no socket is used.

- Rung 1: a 4199-byte record with opcode 260 and 4164 base64 chars triggers
  deterministically; a 128-byte record is the safe input.
- Rung 2: `snprintf` truncation gives `remaining == -2` -> `SIZE_MAX-1`.
- Rung 3: ASan reports `global-buffer-overflow`, `WRITE of size 1` at
  `base64.c:164` via `decode_sniffer.c:47`, `0 bytes after global variable
  'obuf' ... of size 4096`; rc 1.
- Byte control: chosen decoded bytes `MISHE-OO` (`4d 49 53 48 45 2d 4f 4f`)
  land at guard offsets 0 and 128 past `obuf` in the guarded build; the fixed
  build leaves the guard unchanged (`cd`) and is ASan-clean for attack and
  safe inputs. `sh run-all.sh` -> 17 PASS / 0 FAIL, log `replay.log`.
- Exact pins, patch hashes and compiler commands: `PROVENANCE.md`.

## Rung-4 feasibility and ceiling

Rung 3 is confirmed in the real pinned decoder and base64 implementation.
Rung 4 is PARTIAL: packet-derived bytes at two chosen offsets past a 4096-byte
output buffer, in a minimal harness whose `obuf` stands in for `trigger.c`'s
global. No live dsniff process, no UDP/2001 delivery, no libnet/libnids,
no trigger dispatch, no dispatch-table or function-pointer overwrite, no
pointer/IP/command control, no allocator metadata, no rung 5. The reporter's
live-crash observation stays UNKNOWN: libnet and libnids headers are absent
on this host. Independent witness replay (2026-11-24, DM #3598) rebuilt from
a clean archive of commit `5557139` and recorded 17 PASS / 0 FAIL, ASan
WRITE-1 at `base64.c:164` via `decode_sniffer.c:47`, chosen marker at guard
offsets 0 and 128, fixed and safe clean; its steering harness moved marker
content and offsets (Z9KLMNOP@299, W198STR!@63). Verdict: ESTABLISHED AS
LABELED; the live wire path remains UNKNOWN.

## Cheapest next experiment

Provision libnet/libnids headers and build the real `dsniff` binary from the
same pinned tag; run it loopback-only, send the 4199-byte UDP/2001 datagram
from a local generator and observe the ASan/plain crash with fixed and safe
controls. Then inspect the real `.bss` layout after `obuf` for the counters
the issue identifies before claiming any control-flow effect. Independent
witness replay of the harness is complete; only the live UDP/2001 path is
still UNKNOWN.
