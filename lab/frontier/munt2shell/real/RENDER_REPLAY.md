# W185 clean-archive replay receipt (2026-11-24)

Author commit `774ba4d0` ("munt2shell W185: no real-library readback of chosen
overflow byte after dispatch/render"). Replayed from `git archive HEAD
lab/frontier/munt2shell` into a fresh `/tmp/w185-munt-replay`; the gitignored
pinned tarball was copied in and `./prepare_src.sh` verified its sha256
`81f8c462f46bc8901618762ae34cf9de93894ff81f41db73c79472fa3baef875`, all
`PINS.sha256` entries and both regenerated trees (`vuln`, `fixed`).

`./render_probe.sh` rebuilt both `MT32EMU_WITH_TESTING` static libraries from
the regenerated trees and replayed all four cases plus the gdb watchpoint.
All rc values and all six evidence files match the author run after
normalizing ASLR pointers (`0x[0-9a-f]+` -> `0xADDR`) and gdb process ids
(`process N` -> `process PID`): 6/6 files, 0 diffs. The normalized digest over
the sorted six files is
`e97062c595fbfb76abcb4993b313105bd07d5e801ef374dfd818c6af9078bfb5`.

Not an independent witness verdict: this is the author's own clean-archive
replay of a build-variant rung-4 boundary check. Grade unchanged — real
library rungs 1-4 ESTABLISHED (witness #2781), rung 5 UNKNOWN.
