# W184 clean-archive replay receipt (2026-11-24)

Author commit `f7b5491b` ("munt2shell W184: in-library pushSysex consumes
forged top chunk"). Replayed from `git archive HEAD lab/frontier/munt2shell`
at that commit into a fresh temporary directory; the gitignored pinned tarball
was copied in and `./prepare_src.sh` verified it (sha256
`81f8c462f46bc8901618762ae34cf9de93894ff81f41db73c79472fa3baef875`), all
`PINS.sha256` entries and both regenerated trees (`vuln`, `fixed`).

`./push_probe.sh` rebuilt both `MT32EMU_WITH_TESTING` static libraries from
the regenerated trees and replayed all seven cases. All seven rc values and
all seven `.out` files match the author run after normalizing ASLR pointer
values (`0x[0-9a-f]+` -> `0xADDR`); `push-results.txt` matches too. 8/8 files
identical, 0 diffs. Normalized digest over the sorted eight files:
`1e0d0c675fc1cafe28b94a11a05046cb37222c5b8f082e6bb2493977037f7848`.

Not an independent witness verdict: this is the author's own clean-archive
replay of a build-variant rung-4 mechanics lane. Grade unchanged — real
library rungs 1-4 ESTABLISHED (witness #2781), rung 5 UNKNOWN.
