# Frontier brief: rufussbat2shell — Rufus remote SBAT heap overflow

Status 2026-11-27 W369: **STAGED for operator admission and independent witness
replay**. Stage commit `0415fa78`; clean `git archive --format=tar` SHA-256
`178726d9f94a0bbf2e249431fc00576dccbb610cb9c912d41ea10cab18a9c025`
replayed 16/16 pins and `RUN_ALL_OK 11 PASS / 0 FAIL`. Grade R3 confirmed on the
pinned parser; R4 **LIMITED** to a synthetic adjacent victim in a no-PIE/no-canary
lab build. R5 NOT CLAIMED. Inner-socket window 229 (`%464`/`%465`, dead=0) is
live and registered with two panes.


## Verified ground truth (claim, not assumed)

- Advisory: GHSA-hcpc-vq8c-923h, published 2026-11-05, Moderate 6.5,
  CWE-131/CWE-787 (incorrect buffer-size calculation / out-of-bounds write).
  No CVE ID is assigned in the advisory.
  Primary record:
  https://github.com/pbatard/rufus/security/advisories/GHSA-hcpc-vq8c-923h
- Affected: Rufus `>=4.11, <=4.16_BETA`; patched release `4.16`.
- Fixed commit: `842873017f289713a5d5009320c11f31cfee36ed`.
  Exact pre-fix parent: `de4cf676c2aedf73b0ddfc234e420d19c8969c2e`.
- Claim: `GetSbatEntries()` counts LF bytes before converting CR bytes to LF.
  A CR-only `sbat_level.txt` therefore gets a two-entry allocation but one
  parsed entry per CR-separated line. The parser writes attacker-influenced
  product pointers and chosen 32-bit versions beyond that allocation.
- Reachability claim: `CheckForFidoThread()` downloads
  `https://rufus.ie/sbat_level.txt` without a signature and passes any nonempty
  response under 1 KB to `GetSbatEntries()`. Exploitation requires control of
  that response or a trusted TLS-intercepting position. This is a vendor claim;
  no external host was contacted by this lab.


## Source-bound mechanism

Pinned vulnerable `src/parser.c:1626-1637`:

```c
num_entries = 1;
for (i = 0; sbatlevel[i] != '\0'; i++) {
	if (sbatlevel[i] == '\n')
		num_entries++;
	if (sbatlevel[i] == '\r')
		sbatlevel[i] = '\n';
}
sbat_list = calloc(num_entries + 1, sizeof(sbat_entry_t));
```

`src/rufus.h:583-587` defines the x86-64 layout as an 8-byte `char* product`
followed by a 4-byte `uint32_t version` and 4 bytes of alignment padding, so
`sizeof(sbat_entry_t) == 16`. With no LF bytes, `num_entries` remains 1 and the
allocation is 32 bytes: two usable entries plus one zero terminator.

The parse loop at `src/parser.c:1651-1671` writes every nonzero-version line:

```c
sbat_list[num_entries].product = &sbatlevel[i];
...
sbat_list[num_entries].version = strtoul(version_str, NULL, 10);
```

For three CR-separated lines, entry 2 starts exactly at the end of the 32-byte
allocation. Its product field writes an 8-byte pointer into the attacker-owned
download buffer; its version field writes a chosen 32-bit value eight bytes
farther. A 60-line, 350-byte CR-only file stays below the real caller's 1 KB
limit while driving 58 entries out of bounds.

The fixed function converts CR before counting LF. The same 60-line file then
allocates 61 entries and parses cleanly. `src/stdlg.c:1711-1724` performs the
real download/call/terminator-loop sequence; `src/hash.c:2223-2228` later walks
the list with `strcmp`.


## Local experiment

`lab/frontier/rufussbat2shell/harness/driver.c` includes the verbatim pinned
function with `#line` directives preserving upstream line numbers. It reads a
local file into a NUL-terminated `malloc(n + 2)` buffer, matching the download
buffer's extra terminator. No Windows binary, network request, debugger memory
write, shell or command is used.

- Vulnerable ASan, three LF lines: rc 0, `ENTRIES=3`.
- Vulnerable ASan, three CRLF lines: rc 0, `ENTRIES=3`.
- Vulnerable ASan, 60 CR-only lines (350 bytes): rc 134,
  `AddressSanitizer: heap-buffer-overflow`, `WRITE of size 8`, 0 bytes after a
  32-byte region, `GetSbatEntries` at `src/parser.c:1651`.
- Fixed ASan, same 60-line file: rc 0, `ENTRIES=60`.
- Vulnerable ASan, two CR-only lines: parser completes, then the real-style
  terminator loop reads 8 bytes 0 bytes after the 32-byte region. Fixed returns
  `ENTRIES=2` cleanly.
- GCC and Clang each reported `RUN_ALL_OK 11 PASS / 0 FAIL`.


## Rung assessment and scope

- R1: deterministic local trigger through the exact pinned parser.
- R2: attacker input selects the OOB product pointer's offset within the
  download buffer and the adjacent 32-bit version value.
- R3: ASan-confirmed heap-buffer-overflow WRITE-8 and terminator-loop READ-8 on
  the pinned parser.
- R4 **LIMITED**: a link-time `calloc` wrapper places a synthetic victim
  immediately after the real 32-byte list allocation. Entry 2 overwrites the
  victim's prefix and the low 32 bits of its callback. In the plain
  no-PIE/no-canary build, a chosen hexadecimal version equal to
  `benign_marker` transfers control and prints `BENIGN_MARKER`; the fixed build,
  a two-line input, and a `not_called` target do not. The victim guard remains
  `1122334455667788`. This proves chosen 32-bit control of an adjacent callback
  in that synthetic layout, not control of a real Rufus object.
- R5: NOT CLAIMED. No live Rufus/Windows process, remote response, loopback
  service, command or side effect was exercised.

The synthetic victim is deliberately adjacent through `--wrap=calloc`; real
Windows heap adjacency, ASLR, CFG, stack cookies, allocation reuse and the
post-download object layout remain UNKNOWN. The product pointer points to
attacker data but does not by itself make that data executable.


## Cheapest next experiments for the dedicated mind

1. Reproduce the exact function under x86_64 Windows with the real Rufus
   allocator and measure which live object follows the 32-byte list allocation.
2. Test whether the chosen 32-bit version can redirect a same-image pointer
   under ASLR and CFG; preserve the high half and target a useful consumer.
3. Drive a loopback TLS-intercepting download through the unmodified
   `CheckForFidoThread()` path with a lab-trusted certificate, then observe the
   real terminator loop and later `IsRevokedBySbat()` consumer.
4. Only after a real consumer transfer is measured, test a benign command side
   effect with vulnerable/fixed/safe controls.


## Selection notes

Rufus is tractable because the vulnerable function is small, the fix is a
three-line reorder, the triggering file is under 1 KB, and both the full product
pointer and a chosen 32-bit value cross the allocation boundary. The Windows
and trusted-response conditions prevent an R5 claim. W368's unknown wake left no
Rufus artifact; this brief is the first durable Rufus work in the repository.

The W369 read-only advisory sweep also verified GNU Screen CVE-2026-71409 as
the next candidate: `SendCmdMessage()` appends attacker-controlled `STY` to the
global `SocketPath[]` with unchecked `sprintf()`; Screen 5.0.2 adds a length
check and bounded `snprintf()`. No existing Screen/CVE-2026-71409 lane was found.
It is not reworked in this wake; the next frontier action is to pin 5.0.1/5.0.2
and run the cheap ASan `HOME`/`STY` experiment. A same-CVE `FindSocket()` sink
and a 5.0.2 `SendCreateMsg()` sibling fixed in 5.0.3 should be folded into one
Screen mind rather than staged separately.
