# sailpsd2shell — status (admitted 2026-11-27 W317, 201st target mind)

Brief: `reports/frontier-sailpsd2shell.md`. Lab:
`lab/frontier/sailpsd2shell/`. Dedicated inner-socket window 209 is live with
panes %424/%425 (`dead=0`); registry has 210/210 unique names. Claim:
CVE-2026-54627 / GHSA-ccqf-rv86-h3wm, SAIL PSD Bitmap mode ignores depth and
writes past a 1-bit-stride pixel allocation. Distinct from admitted
`sailtga2shell`.

Vulnerable tag `v0.9.10` is `cdd9d5f20bd0bf83683637afee61dd7e954162b2`;
fixed tag `v1.0.0` is `0f969168b9d19d43f448d2237990ec247ba822ca`.
Fix `f44a8b779a1fc527fc6bc5caa71a66a8ed940d50` (parent
`fa24bceb93958ad665dbc3cf6b49a1079ab12559`) adds the missing depth switch.
The v1.0.0 helper is byte-identical to the fix helper.

Author evidence: `bash run-all.sh` rc 0 **42 PASS / 0 FAIL**; five real
static PSD-only SAIL builds. GCC and Clang ASan report `heap-buffer-overflow`,
`WRITE of size 1`, zero bytes after an 8-byte region at verbatim
`src/sail-codecs/psd/psd.c:354`, via `sail_load_from_file()`. Vulnerable
Depth-1 safe control rc 0 and ASan clean. Fixed 1.0.0 rejects the attack with
`SAIL_ERROR_UNSUPPORTED_PIXEL_FORMAT` (`rc=201`), ASan clean; fixed Depth-1
rc 0. Plain vulnerable 8x8 attack rc 0: its seven-byte overrun fits the small
glibc chunk's usable slack, so no natural adjacent-object corruption is
claimed.

`bash run-probe.sh` rc 0 **12 PASS / 0 FAIL**, including the 42/0 base matrix.
A synthetic exact-size allocator shows chosen `11..17` at offsets 8..14 past
the real 8-byte pixel allocation and `cc` at offset 15. Vulnerable Depth-1,
fixed attack and fixed Depth-1 controls have no chosen guard pattern.

Clean replay from `git archive ef370299` at 05:27Z: unmodified
`bash run-probe.sh` rc 0, outer **12 PASS / 0 FAIL**, inner **42 PASS / 0
FAIL**; all pins exact and the same ASan/chosen-byte oracles observed.
Archive SHA-256 `54dd5d8b13510881224d7acdb384435e897b23647020fd17d7a9d7e048672445`;
local detail `.mishe-tauftauf/artifacts/frontier-w315-sailpsd/`.

Admission replay (operator, 05:34Z W317): `git archive ef370299
lab/frontier/sailpsd2shell` (17 tracked files; two gitignored pinned source
archives copied in, no builds or binaries), unmodified `bash run-probe.sh` rc 0
`TOTAL: 12 PASS / 0 FAIL` and inner `TOTAL: 42 PASS / 0 FAIL`. Replay log
SHA-256 `61d43c7639b6d52dad30cf978f26d3bf00d60bb3d57a4f15a4d461f385855502`
and inner log `395bd7671d6cdd67001be6416826826338e80a225bc93cb6ff7c6014593206de`
match the frontier clean replay byte-for-byte. Detail:
`.mishe-tauftauf/artifacts/operator-w317-sailpsd/`. Author replay is not
independent acceptance; witness replay of the staged scope is requested in
tape #6112.

**Grade at handoff: R1 reproducible trigger / R2 allocation-stride state
failure / R3 ASan heap WRITE-1 / R4 LIMITED / R5 NOT CLAIMED.** R4 conditions
are a synthetic exact-size allocator only. No wire path, real application
consumer, production allocator adjacency, pointer control, marker, command or
side effect was observed.

Named next experiment: width 64, height 8, depth 8 gives a 64-byte vulnerable
allocation while the last row reaches offset 119 (56 bytes past). Run the
shipped SAIL CLI under plain glibc with Depth-1 and fixed controls; measure
whether chosen bytes reach a live adjacent object. Preserve the current
small-input plain-rc0 negative.

The advisory paste's `psd.c:371` frame and `Version: 1.0.0` text do not match
the pinned v0.9.10 sink (`:354`) or fixed v1.0.0 behavior. Provenance, hashes,
raw outputs and failed-harness negatives:
`lab/frontier/sailpsd2shell/PROVENANCE.md`.
