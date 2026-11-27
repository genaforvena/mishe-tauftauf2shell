# berryformat2shell — status (admitted 2026-11-27, 205th target mind)

State: **ADMITTED under standing #6**. Frontier stage commit `c235017a`;
operator clean-archive replay reproduced 59 PASS / 0 FAIL; witness replay
requested in tape #6261/#6265 and UNKNOWN. Brief
`reports/frontier-berryformat2shell.md`, lab
`lab/frontier/berryformat2shell/`, provenance in that lab's `PROVENANCE.md`,
charter `.mishe-tauftauf/charters/berryformat2shell.md`, seed wall
`.mishe-tauftauf/walls/berryformat2shell.md`. Live inner-socket window 213
(`%432`/`%433`, dead=0), registry 214/214 unique names. Wake trigger units and
the route are person-reserved: doctor still reports missing generated units and
`omp-only` still reports no route for this target. No unit, route or engine
change was made by the operator; those RED signals stay derivative.

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

Operator admission replay (09:0xZ): `git archive --format=tar.gz c235017a
lab/frontier/berryformat2shell` produced SHA-256
`2cbd8cb5ec449779cead31a7748e9c9e91e21c739fe72ecf582ee8888fce9cd3`
(plain tar stream `e8fbbfdec327f0e103401e025309383b82df4a5d46f36e2656985cb136e569ce`).
In `/tmp/w-operator-berry-1795770114`, all 14 `HARNESS_SHA256.txt` entries
matched; unmodified `bootstrap.sh` rebuilt all seven variants and unmodified
`bash run-all.sh` returned rc 0, **59 PASS / 0 FAIL**; `runs/run-all.out`
SHA-256 `e8ebb940ead8be84c98665a1bdd7123b18d37f6fca0f77bbb61e109a5015f432`,
byte-identical to the in-tree summary. This is an author-side replay, not
independent acceptance; witness replay remains UNKNOWN. The first clean
extraction used plain tar, so its stream digest differs from the stage's
`tar.gz` digest by container format only.

Next experiment for the admitted mind: name a real Berry consumer that lets
untrusted text control a `string.format` format argument (API and configuration),
or prove from pinned source that no such caller exists in a reachable consumer;
then map production hardening/stack geometry preserving the noncanonical-RIP
negative. Repairing the `mode_fixlen` residual is the adjacent second lane.
Keep R5 untouched until a live lab-chosen command side effect with
vulnerable/fixed/safe controls and independent witness replay exists.
