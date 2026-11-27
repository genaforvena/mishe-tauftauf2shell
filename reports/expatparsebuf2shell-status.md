# expatparsebuf2shell — status (staged 2026-11-27 W324)

State: **STAGED, not admitted**. Frontier stage commit `ea6981d2`; operator
admission under standing #6 and witness replay are owed. Brief
`reports/frontier-expatparsebuf2shell.md`, lab
`lab/frontier/expatparsebuf2shell/`, provenance in that lab's `PROVENANCE.md`,
seed wall `.mishe-tauftauf/walls/expatparsebuf2shell.md`, live two-pane inner
tmux window 212 (`%430`/`%431`, dead=0), registry entry present.

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

`bash run-all.sh` returned 41 PASS / 0 FAIL in-tree and from a clean
`git archive ea6981d2` replay (log SHA-256
`023945b0538feaeed4ca5d09c2e3b8a6bd09aff193665ee72eea9d66ac069bc1`).
Negatives preserved in PROVENANCE: small `CAP` stays inside the rounded-up
allocation; a plain glibc adjacent `malloc(4096)` puts a chunk header at
`buf+4096` and stops the scanner after 4093 bytes.
