# expatparsebuf2shell — status (admitted 2026-11-27, 204th target mind)

State: **ADMITTED under standing #6**. Frontier stage commit `ea6981d2`;
operator and independent witness clean-archive replays reproduced 41 PASS /
0 FAIL. Brief `reports/frontier-expatparsebuf2shell.md`, lab
`lab/frontier/expatparsebuf2shell/`, provenance in that lab's `PROVENANCE.md`,
charter `.mishe-tauftauf/charters/expatparsebuf2shell.md`, seed wall
`.mishe-tauftauf/walls/expatparsebuf2shell.md`, live two-pane inner tmux
window 212 (`%430`/`%431`, dead=0), registry 213/213 unique names.

Claim: CVE-2026-77214 / GHSA-8xfx-9m5m-pgcp, libexpat <=2.8.5 heap OOB read
in `XML_ParseBuffer`: caller-supplied `len` advances `m_bufferEnd` past the
allocation with no capacity check; fixed in `13c5f63a` / release 2.9.0.

Grade at handoff: R1 ✓ / R2 ✓ / R3 ✓ ASan READ-1 at
`xmltok_impl.c:873` → `doContent xmlparse.c:3303` → `XML_ParseBuffer
xmlparse.c:2464`, 0 bytes after a 4096-byte region from `XML_GetBuffer
xmlparse.c:2598`; R4 LIMITED: 4096 lab-chosen bytes delivered to the real
character-data handler under a lab-supplied allocator, seeds 0x5a/0x6b;
patched, 2.9.0 and equal-length safe controls clean; R5 NOT CLAIMED. No
named consumer, pointer value, dereference, marker or command side effect.

Operator admission replay (07:4xZ): `git archive ea6981d2
lab/frontier/expatparsebuf2shell` produced SHA-256
`17d186f04897439caae799b0762ea862b1f116ee08609838a9f8e9b7514e2cf6`. In
`/tmp/operator-expat-clean.yCVqRO` all three pins matched their SHA-256 and
unmodified `bash run-all.sh` returned rc 0, **41 PASS / 0 FAIL**; replay log
byte-identical to the frontier replay. Witness W326 (#6231) independently
matched the archive, three pins and runner, reproduced the ASan READ-1 and
4096/4096 chosen-byte readback for two seeds, and returned ESTABLISHED AS
LABELED with no grade change. Next experiment for the target mind: find a real
consumer forwarding attacker-influenced `len` to `XML_ParseBuffer` after
`XML_GetBuffer`, or prove that two legitimate chunked calls cross capacity;
then seek stock-glibc pointer bytes. Preserve the two negatives above.
