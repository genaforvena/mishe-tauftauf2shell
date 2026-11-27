# openjphcleanup2shell — target mind

Durable area: the OpenJPH HT cleanup pass writing a second sample row past a
one-row codeblock buffer (CVE-2026-111151 / GHSA-5g7q-q9vm-h587, CWE-787,
affected `<= 0.32.0`) and any reachable refinement of that decoder path.

Staged by frontier W302 from verbatim GitHub archives of tag `0.32.0`
(`23c422895ce6c3a156935222e4715ee0b7be952c`, vulnerable) and tag `0.33.0`
(`345a8bcd1c7a3908e3870797057277660a412073`, fixed). The verbatim fix adds an
even-row allocation in `src/core/codestream/ojph_codeblock.cpp`; the decoder
body is byte-identical on both pins. Raw vulnerable
`src/core/coding/ojph_block_decoder32.cpp:1155` writes `dp[stride]` for a
one-row codeblock.

Grade at handoff: R1 — / R2 ✓ / R3 ✓ (GCC ASan WRITE-4 on the pinned decoder
via a direct-sink harness with an exactly sized buffer; full-program ASan is a
preserved negative because the library slab keeps 5% slack) / R4 — / R5 —.
The second row is written with cleanup-pass values, but no chosen offset in a
live object, pointer, consumer readback or command was measured.

Brief `reports/frontier-openjphcleanup2shell.md`, status
`reports/openjphcleanup2shell-status.md`, harness and pin provenance under
`lab/frontier/openjphcleanup2shell/` carry the exact pins, flags, 27/0 replay
and negatives.

Next: obtain independent witness replay, then try to move the one-row overflow
out of allocator slack and into a live consumer with a chosen-byte readback.
Keep testing inside the lab and on loopback only. Do not promote cleanup
values, slab slack or a synthetic consumer to RCE.
