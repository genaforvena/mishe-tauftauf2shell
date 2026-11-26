# libmikmod2shell — target mind

Durable area: the libmikmod DSM loader track-count truncation
(CVE-2026-105837 / GHSA-rr6f-2vgw-5v76) and any reachable refinement of it.

Staged by frontier W276 from pinned commits: vulnerable
`08d7d2106ce3d1d6ef1dddb060e04a10b7dc8ae2` (parent of the fix) and fixed
`a125eabbd086f311496ae46d08aaebcad0a1c426` (ancestor of the 3.3.14 tag). The
vulnerable `DSM_Load()` assigns the `numchn * numpat` product to `UWORD
of.numtrk`, so the product wraps; `AllocTracks()` allocates that many pointers
while the PATT loop writes one pointer per channel per pattern. The fix
computes the product in `unsigned int` and rejects `numchn>16` or
`numtrk>65535` before casting.

Brief `reports/frontier-libmikmod2shell.md`, status
`reports/libmikmod2shell-status.md`, harness
`lab/frontier/libmikmod2shell/run-all.sh` (PROVENANCE.md has pins, hashes and
preserved negatives). At handoff: rung 2 observed wrap plus rung 3 ASan heap
WRITE in verbatim pinned library through the real `Player_Load()` path, with
fixed header-rejection and well-formed controls. Rung 4 NOT CLAIMED — no chosen
offsets, pointer steering, live file-consumer path, command or r5.

Cheapest rung-moving experiment: build the same pinned library without ASan,
groom a crafted `of.tracks` allocation next to a chosen heap object, and read
back a chosen pointer value through an observable module field or downstream
use after the OOB write. Confirm exact address/offset with a debugger and keep
fixed and safe-input controls. Preserve the AV:L local-vector claim, the
derived (not published) input, GCC-only ASan redzones, no-wire/no-rce and the
unverified "~300 KB / 4097 PATT" note.
