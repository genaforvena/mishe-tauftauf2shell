# berryformat2shell — status (staged 2026-11-27 W326)

State: **STAGED for operator admission; admission and independent witness
verdict UNKNOWN.** Replay commit `7f4f6615`; clean archive SHA-256
`3473450002c83cc6ea7aa00c971b81d58394bc54f31748be4abea7149c228308`, all
pin/harness hashes matched, 59 PASS / 0 FAIL, summary log `e8ebb940…`.
Brief `reports/frontier-berryformat2shell.md`, lab
`lab/frontier/berryformat2shell/`, provenance in that lab's `PROVENANCE.md`,
charter `.mishe-tauftauf/charters/berryformat2shell.md`, seed wall
`.mishe-tauftauf/walls/berryformat2shell.md`. Live inner-socket window 213
(`%432`/`%433`, dead=0), registry 214/214 unique names.

Finding: Berry 1.1.0 `string.format` calls `get_mode` with `char mode[32]`;
`get_mode` copies an attacker-length flag/conversion run with no destination
size. This is distinct from CVE-2026-3285's related one-byte lexer OOB read.
No CVE/GHSA for the format write is known.

Grade at handoff: R1 ✓ / R2 ✓ / R3 ✓ ASan `WRITE of size 225` at
`src/be_strlib.c:542` / R4 LIMITED / R5 NOT CLAIMED. In an explicitly
unprotected O0 build, 224 chosen flag bytes overwrite the saved-RIP slot with
`2b23302d2b23302d` (noncanonical); the process crashes through corrupted
locals before returning there. Default O2 hardening aborts. No real consumer,
network path, controlled branch, pointer dereference, marker or command was
observed.

Controls: local 1.1.0 backport and exact upstream fix `7149c59a` are clean for
the long-`%s` input; safe format/numeric/lexer inputs are clean. The exact fix
still has a separate numeric-format ASan WRITE-3 in `mode_fixlen:627` (local
backport `:561`); this residual is preserved, not hidden by an extra repair.
`bash run-all.sh`: 59 PASS / 0 FAIL. Runner SHA-256
`fe6435d8609af605fc9aa5b16593186287ca34f3d9c75496c7364588be490633`.

Next: find a real consumer that lets untrusted text control a Berry format
string, map production hardening/stack layout, and repair the `mode_fixlen`
residual. R5 requires a live lab-chosen command side effect with
vulnerable/fixed/safe controls and independent witness replay.
