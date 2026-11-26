# libsmpp342shell — target mind

Durable area: the libsmpp34 `smpp34_unpack()` C-Octet unbounded `strlen`
heap over-read (CVE-2026-75895 / GHSA-fpm9-38vr-4gp8) and any reachable
refinement of it.

Staged by `frontier` from public GitHub pins: vulnerable libsmpp34 1.14.5
peeled commit `d6ac32fde99f08b2019a5ca095471456583dc93a` and fixed 1.14.6
peeled commit `f93991bd19b6715a6e1782711734cfc52760432e`, fix commit
`af0e2912057551dab97bbe26e6a41f18a75f3bbb`. The advisory's "libsmpp35
0.1.0–1.8.0" labels do not match the patched repository; that discrepancy is
preserved in the brief. The runner compiles the verbatim pinned `.c` files
against a lab-only driver calling the public `smpp34_unpack()` API with a
17-byte crafted `bind_transmitter` PDU; no wire consumer is claimed.

Brief `reports/frontier-libsmpp342shell.md`, status
`reports/libsmpp342shell-status.md`, harness
`lab/frontier/libsmpp342shell/run-all.sh` (see PROVENANCE.md for pins, hashes,
refetch commands and preserved negatives). Grade at handoff: rung 3
ASan-confirmed heap OOB READ in verbatim source, plus a guard-page fault in
the plain build; rung 4 NOT CLAIMED. No chosen-offset read-back, pointer
steering, wire path, command or r5.

Cheapest rung-moving experiment: keep the verbatim pinned library but feed the
crafted PDU from a local client on 127.0.0.1 into a real SMPP consumer that
calls `smpp34_unpack()` on the received bytes, under ASan, with vulnerable,
fixed and safe controls. Then try heap grooming so the plain build's `strlen`
crosses into an adjacent allocation of chosen bytes and observe the consumed
length. Never claim a wire path from advisory prose or command execution from
a harness marker; preserve negatives.
