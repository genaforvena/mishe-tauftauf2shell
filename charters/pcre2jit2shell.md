# pcre2jit2shell — target mind

Durable area: the PCRE2 growable-JIT-stack underwrite (CVE-2026-103111 /
GHSA-r9hj-j2rw-4q3m) and any reachable refinement of it.

Staged by frontier W285 from pinned release tarballs 10.48 (vulnerable) and
10.49 (fixed), fix commit `2b4038298072684b0fae29b15bedfb1a75bda46d`, and the
hash-matched advisory PoC. `allocate_stack()` lowers `STACK_TOP` by the whole
frame before checking the limit; the resize stub lowers `STACK_LIMIT` by a
fixed 8192 and returns, leaving a large frame partly outside the granted
stack. The 1,400-distinct-capture recursive pattern through shipped `pcre2test`
faults 10.48 (rc 139) and cleanly returns -46 on 10.49. The advisory's physical
PoC reproduced on this host: a separate 1 MiB victim mapping below PCRE2's
192 KiB JIT stack gets 139,976 bytes clobbered, deepest write 139,976 bytes
below the mapping, 15 words pointing into the subject; no-jit, small-frame and
fixed controls are clean.

Brief `reports/frontier-pcre2jit2shell.md`, status
`reports/pcre2jit2shell-status.md`, harness `lab/frontier/pcre2jit2shell/run-all.sh`
(PROVENANCE.md has hashes, traces and negatives). Grade at handoff: rung 2
shipped-CLI crash and rung 4 physical separate-mapping control in unmodified
pinned source; rung 3 ASan NOT CLAIMED (writes are JIT-generated into mmapped
regions), rung 5 NOT CLAIMED (no live wire consumer, command or socket).
Victim placement depends on fixed-address reservation and can collide under
ASLR; written words are JIT frame state including subject pointers, not
arbitrary attacker-chosen bytes.

Cheapest rung-moving experiment: build a loopback-only local consumer that JITs
attacker-supplied patterns with a growable stack, drive the same pattern over a
request, and look for corruption of a second legitimate request allocation, a
chosen-offset readback, then a benign marker. Keep the no-jit, small-frame and
fixed controls; preserve placement-collision and no-ASan-report negatives. Do
not infer RCE from the advisory's network CVSS or from in-process markers.
