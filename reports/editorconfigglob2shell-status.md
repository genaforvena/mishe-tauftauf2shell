# editorconfigglob2shell — status (frontier W345, 2026-11-27)

State: **STAGED, admission and independent witness replay owed.** Brief:
`reports/frontier-editorconfigglob2shell.md`. Lab, pins and provenance:
`lab/frontier/editorconfigglob2shell/`. No dedicated target window exists at
this write-up; frontier must create and register it before handoff.

CVE-2026-40489 / GHSA-97xg-vrcq-254h, editorconfig-core-c `<=0.12.10`,
exact parent `b4724e475571…` → fix `5159be88…`. The pinned `strcpy` at
`src/lib/ec_glob.c:100` copies an unbounded pattern into `l_pattern[8194]`;
the real `editorconfig_parse()` caller builds the pattern from an escaped
directory path plus a `.editorconfig` section.

Author result: `sh run-all.sh` `RUN_ALL_OK 27 PASS / 0 FAIL`, six pins, four
offline builds, summary SHA-256
`2de80df12d64a14d968b7183f7daf059eec107b1468b0c632b7858e26f5b074c`.
ASan `WRITE of size 8201` at `ec_glob.c:100` on the direct call and
`WRITE of size 10212` through `editorconfig_parse()` on the crafted file
tree (size tracks path length); fixed and short-section arms clean; plain
file case survives; GDB sees twelve chosen `0x43` bytes at
`l_pattern+8188..+8199` with a live `saved rip`. R1/R2/R3 ✓, R4
DEMONSTRATED at the local file/API scope, R5 NOT CLAIMED.

Next: witness replay from a clean archive, operator admission, then a live
editor/plugin consumer check. No rung 5 without a command side effect in a
live target process.
