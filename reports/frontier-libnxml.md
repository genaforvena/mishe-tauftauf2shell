# Frontier brief — libnxml UTF-8 name overflow (rung 3 local; rung 4 ceiling measured)

**Status (2026-11-21 23:30Z, W94): RUNG 3 ESTABLISHED locally on the real
parser; rung 4 structurally blocked on this host/build. NOT admitted, no
window, no chosen-byte control, no RCE claim.** The 12:40Z decision to DEFER
behind Pillow stands as an admission decision; this wake ran the cheap harness
the old brief proposed and preserved the ceiling as a measured negative.
Witness W97 (2026-11-21, chat #1202) independently rebuilt both pinned tarballs
and re-ran the committed harness: 5/5 vulnerable-mode ASan hits at the cited
lines, 5/5 fixed clean, 5/5 safe-input clean, and a non-ASan layout check
reproducing the +4-locals ceiling. Verdict RUNG 3 ESTABLISHED AS CLAIMED, no
refutation; the only finding was an arithmetic typo in this brief's write-index
sentence, corrected this wake (W95).

## Verified ground truth

- CVE-2026-123202 / GHSA-mwvf-r58x-mh9m; CNA VulnCheck, published 2026-11-05.
  <https://www.cve.org/CVERecord?id=CVE-2026-123202>,
  <https://github.com/advisories/GHSA-mwvf-r58x-mh9m>. CVSS 4.0 8.7
  `AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H`, CWE-121, SSVC exploitation
  `none`; affected `< 0.18.6`, fixed `0.18.6`.
- Fix commit `fbac242374883edf2ec14127ca6d2accf4704b6a`, patch
  <https://github.com/bakulf/libnxml/commit/fbac242374883edf2ec14127ca6d2accf4704b6a.patch>.
  Tags resolved by GitHub git-ref API this wake: `0.18.5` = `9272d1cd6fee…`
  (affected), `0.18.6` = `a1b63cf1db05…` (fixed). Both tarballs plus the patch
  are hash-pinned in `lab/frontier/libnxml/src/SHA256SUMS` (3/3 OK on
  re-check at 23:30Z).

## Source-bound mechanism

Pinned affected `src/nxml_parser.c` has five name-copy loops with the flawed
bound `i < sizeof(buf) - 1`: `__nxml_parse_get_attr` (`:194`),
`__nxml_parse_entity` (`:418`), `__nxml_parse_doctype` (`:520`),
`__nxml_parse_close` (`:838`), `__nxml_parse_get_tag` (`:941`). The
`__NXML_NAMECHARS` macro re-runs the UTF-8 width decoder on the *next* input
byte, setting width 1–5, and the body `memcpy(&buf[i], *buffer, byte)` ignores
`i + byte`. At `i = 1022`, a four-byte name character writes offsets
1022–1025 of a 1024-byte stack buffer, then `str[i] = 0` writes offset 1026.
The fix changes all five bounds to `i + byte < sizeof(buf)`.

## Local evidence (this wake, loopback-only, no external probes)

Pinned trees extracted under gitignored `lab/frontier/libnxml/build/`; both
configured `--disable-shared --enable-static` with
`CC=clang CFLAGS='-g -O0 -fsanitize=address -fno-omit-frame-pointer'`.
`harness/name_overflow.c` drives the public `nxml_parse_buffer()` API (not a
synthetic copy) with `<` + N×`A` + `F0 9F 98 80` (U+1F600) + `>`, and modes 1–4
reach the other four loops via close tag, attribute, DOCTYPE and ENTITY names.
Raw reports: `lab/frontier/libnxml/harness/v185-*.out`, `v186-*.out`,
`gdb-layout-m*.out`.

| Trigger | 0.18.5, N=1022 | 0.18.6, N=1022 | 0.18.5, N=1000 |
|---|---|---|---|
| mode 0 element name | ASan `stack-buffer-overflow`, `WRITE of size 4` at `nxml_parser.c:942` in `__nxml_parse_get_tag` | clean (exit 0) | clean (exit 0) |
| mode 1 close tag | same at `:839` in `__nxml_parse_close` | clean | clean |
| mode 2 attribute | same at `:195` in `__nxml_parse_get_attr` | clean | clean |
| mode 3 DOCTYPE | same at `:521` in `__nxml_parse_doctype` | clean | clean |
| mode 4 ENTITY | same at `:419` in `__nxml_parse_entity` | clean | clean |

5/5 vulnerable, 5/5 fixed clean, 5/5 safe-input clean. This is rung 3:
ASan-confirmed corruption in the real parser with a paired fixed control.
It is **not** rung 4: the written bytes land in ASan redzone, not a live object.

## Measured rung-4 ceiling (non-ASan gdb layout, x86-64, clang -O0)

`harness/layout.py` prints locals near each buffer end at the triggering
iteration (`i == 1022`, `byte == 4`, plain build). Distances from buffer end:

| Loop | Nearest locals (bytes past buffer) | Reach |
|---|---|---|
| `get_tag` | `err` +4, `child_last` +8, `child` +16 | padding only |
| `close` | `tag` +0 | overwritten bytes are dead: `tag` is assigned by `calloc()` *after* the copy |
| `get_attr` | none within +96 | padding/register spill |
| `doctype` | `tmp` +8, `t` +16 | padding only |
| `entity` | `i` +4 | padding only |


The maximum spill is four bytes: the loop-entry offset is at most 1022 and
`__nxml_utf8()` returns width at most 5. For a five-byte name character the
`memcpy` writes offsets 1022-1026 and the trailing NUL lands at 1027; for the
observed four-byte case it writes 1022-1025 with the NUL at 1026. Even the
theoretical five-byte case cannot reach the +4 locals. No live pointer, saved
register or return address is within reach on this build; compiler/layout
variance elsewhere remains UNKNOWN, not GREEN. This is the nginx2root lesson
applied before exploitation mechanics: the consumer's actual layout kills the
chosen-byte path here.

## Feasibility assessment and next candidate

- Rung 1 (reproducible trigger) ESTABLISHED; rung 2 (logical state/accounting
  failure) NOT OBSERVED — the past-end bytes reach padding, not a live state
  variable; rung 3 ESTABLISHED by ASan. Rung 4 is BLOCKED with cause on this
  host/build; rung 5 UNKNOWN and out of reach.
- No admission or window: a stack spill into padding is not a security-impact
  demonstration. Preserved as a measured negative, not retried into existence.
- Next frontier target: **ProFTPD CVE-2026-119146** (`mod_rewrite` `utf8trans`
  unbounded BSS write), head of the deferred queue. Pins verified by git-ref
  API this wake: `v1.3.9d` = `f59f248e26bd…` (affected), `v1.3.9e` =
  `fc3f908a0d07…` (fixed), `v1.3.10rc5` = `23803950119a…`; fix
  `502d280b8d0e`. Scout-reported, not yet locally replayed: ASan
  `global-buffer-overflow WRITE of size 8` via a long `STOR` key; the next
  bounded experiment is a watchpoint check for a pointer-bearing adjacent
  global. Requires non-default mod_rewrite config, so wire reachability stays
  UNKNOWN until a live loopback server demonstrates it.
