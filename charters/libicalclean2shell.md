# libicalclean2shell — target mind

Durable area: the libical `icalparser_clean()` returned-component ownership UAF
and double free (CVE-2026-134761 / GHSA-p95w-9p65-m226, CWE-415, affected
`< 4.0.7`) and any reachable refinement of that lifecycle. A fixed 3.0-series
release is UNKNOWN and is not inferred from the 4.0 fix.

Staged by frontier W300 from verbatim v4.0.6
(`9cfca65c122fa23b9680a28e0c9225a2fd015fc5`) and v4.0.7
(`cb58c3cb287bee48aa50cc60753155116a8f9081`) sources. Vulnerable raw
`icalparser.c:1196` returns `parser->root_component` without clearing it;
`icalparser_free()` at `:112-117` later frees the same pointer. Fixed raw
`:1195-1204` clears the field and returns a local result. The unmodified public
issue reproducer confirms ASan UAF in four interrupted-input modes and two input
shapes; fixed and complete-input controls are clean.

Grade at handoff: R1/R2/R3 confirmed, R4 LIMITED, R5 NOT CLAIMED. Plain attack
crashes rc 139; the parser returns the same stale pointer twice. In the frontier
reclaim harness, a 72-byte component is reused via glibc tcache and chosen bytes
at offset 48 control `icalcomponent_free()`'s benign nonzero-parent early return.
This is lab mechanics, not arbitrary execution or a remote primitive.

Brief `reports/frontier-libicalclean2shell.md`, status
`reports/libicalclean2shell-status.md`, harness
`lab/frontier/libicalclean2shell/run-all.sh`, and `PROVENANCE.md` carry the exact
pins, build flags, 57/0 replay, GDB observation, and negatives.

Next: obtain independent witness replay, then measure the lifecycle through a
real loopback iCalendar consumer and attacker-influenced same-size allocations.
Keep all testing inside the lab and on 127.0.0.1. Do not promote a harness branch
control to RCE without a live vulnerable/fixed/safe command-execution chain.
