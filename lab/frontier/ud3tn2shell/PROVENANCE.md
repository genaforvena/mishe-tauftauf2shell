# µD3TN CVE-2026-121510 — provenance and replay

Frontier W109, 2026-11-22. All fetching was provisioning of public sources or
reads of public advisory/patch pages. No probe, scan or traffic to any external
system; all daemon runs bound to 127.0.0.1 and were started and stopped by the
harness in this directory.

## Provisioning

- Authoritative repo: `https://gitlab.com/d3tn/ud3tn`. The two release
  archives at `/-/archive/<tag>/ud3tn-<tag>.tar.gz` returned HTTP 429 on this
  host, so sources came from `git clone --filter=blob:none --no-checkout` plus
  `git archive` at the tags. Both tag SHAs were read back from the local clone
  and match the advisory records (see `src/PINS.txt`).
- Submodules at the pinned gitlinks: nanopb and tinycbor were cloned at the
  exact commits recorded in each tag's tree, stripped of `.git`, and copied
  into both extracted trees. `external/unity` is only needed for unit tests.
- Both trees built with `make posix -j8 sanitize=yes sanitize-strict=yes
  DISABLE_JSON=0` (the last option works around the absent `libjansson-dev`).
  A copy of v0.15.1 was rebuilt without sanitizers for the gdb readback.

## Replay

From this directory:

    python3 harness/wire_trigger.py --src "$PWD/src" --outdir "$PWD/replay" \
        --vuln-port 19224 --fixed-port 19230
    python3 harness/gdb_readback.py \
        --binary "$PWD/src/ud3tn-v0.15.1-plain/build/posix/ud3tn" \
        --outdir "$PWD/replay-gdb" --port 19234 --marker 90

`wire_trigger.py` starts a daemon with node ID `dtn://ud3tn.dtn/`, sends the
vendor BPv6 admin-record bundle over CBOR-framed MTCP to loopback, and tears
the daemon down. It refreshes the bundle's 5-byte SDNV creation timestamp
because the published value is stale on this host's clock; no length field
changes. Ports default to fresh values; pass different ones if the host has
other lab daemons listening. `gdb_readback.py` drives one bundle into a plain
build and dumps the source-EID buffer after 20 stores.

Expected: ASan WRITE size 1 at `components/bundle6/reports.c:439` on v0.15.1
for markers 0x41 and 0x5a; clean on v0.15.1 with source-EID length 8 and on
v0.15.2 with the trigger; gdb readback shows 20 consecutive marker bytes at
offsets 0..19 of a one-byte allocation.

`harness/evidence/` holds the captured logs. `harness/EVIDENCE_HASHES.txt`
hashes them after normalizing timestamps, PIDs, addresses, paths and thread
IDs, so an independent replay is byte-identical at that level.

## Scope boundary

The write address is the one-byte heap chunk plus a sequential `uint16_t`
counter; address steering is not claimed. No command execution, no heap
grooming toward a function pointer and no witness replay occurred here.
