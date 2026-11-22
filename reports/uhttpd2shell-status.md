# uhttpd2shell — status

Admitted 2026-11-22 ~21:2xZ under standing approval #6 as the 86th engine
route. Charter `.mishe-tauftauf/charters/uhttpd2shell.md` and seed wall
`.mishe-tauftauf/walls/uhttpd2shell.md` were created by frontier at W122; the
two-pane window (inner index 91, registry entry 92) already existed and was
adopted, not duplicated. Admission added the hy4-flash route and three units
from the exact full-flag sync (pin
`0d686bbad55c849e88334da64efff9da88ad528a`; `written 9, removed 0` across all
three targets). Pinned `doctor` and `check-omp-only.py` are GREEN.

- Claim: GHSA-2mpg-6wp5-435p, "uhttpd: unauthenticated out-of-bounds write via
  `params` type confusion in POST /ubus/call/", published 2026-08-03 by `jow-`,
  High, CVSS v3.1 7.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`). The advisory
  demonstrates **denial of service only** and explicitly states that controlled
  corruption and code execution were not demonstrated; any RCE scoring is
  claim text. Source: `lab/frontier/uhttpd2shell/harness/PROVENANCE.md`.
- Primitive: the JSON-RPC policy declares `params` as
  `BLOBMSG_TYPE_UNSPEC`, and `uh_ubus_send_request()` assumes a container.
  With `"params":1` the 20-byte `BLOBMSG_TYPE_INT32` attribute is iterated as a
  `blob_attr`: `blob_len()` underflows to `0xFFFFFFFD`, `blobmsg_name(cur)`
  points 2 bytes past the 20-byte `blob_memdup` allocation (OOB read in
  `strcmp`), and `blobmsg_add_field()` truncates that underflowed length to
  `4294967293` for the final `memcpy`. The fix is a four-line guard:
  `if (args && blobmsg_type(args) != BLOBMSG_TYPE_TABLE) return ...ERROR_PARAMS`.
- Pins: vulnerable `f682ccabee9ed5f39dd3b0aaf96228975eeb478d` (shipped
  `7b1bec45` is byte-identical on `ubus.c`), fixed
  `e76736e5676fb25536b27d45865eb4153c68aca3`, libubox
  `a396f38a8568a1d670c240465cd8d24fdfdf6463`. Seven blob digests in
  `harness/pins/PIN_HASHES.txt`.
- Evidence (`cd lab/frontier/uhttpd2shell && bash harness/run.sh`, 30 PASS /
  0 FAIL twice with gcc 13.3.0 and clang 18.1.3, plus a clean `git archive
  d6afa99` replay; `round2-pass.txt` SHA-256
  `c3b2b9d19d6950090c4efdbc2b5e483881f1d23b297beea41343c6dc5622fc66`):
  REAL mode with an exact 20-byte allocation gives ASan
  `heap-buffer-overflow READ of size 1`, 2 bytes past the region, frames
  `strcmp` → verbatim `vuln_uh_ubus_send_request`; fixed pin returns
  `ERROR_PARAMS` before the loop with `INVOKED=0`. MODEL mode substitutes an
  instrumented final sink: `WRITE_LEN=4294967293`, 16 chosen `41…`/`5a…` bytes
  at `WRITE_OFF=20`, ASan `WRITE of size 16` into `malloc(8)`; a well-formed
  TABLE `params` writes only 4 bytes. The ~4 GiB `memcpy` is never executed
  locally — default ASan halts at the earlier read, and a recover-mode write
  would risk the lab memory guard.
- Grade: rungs 1/2 and rung 3 (ASan OOB read in verbatim pinned code over real
  pinned libubox) at direct-call scope; rung 4 chosen bytes at a chosen offset
  only at the **modeled-sink** scope. Ceiling: network-facing and
  unauthenticated per the advisory's null-SID ACL configuration, but no live
  uhttpd process, HTTP wire, rpcd, ACL-chain replay, heap grooming, pointer
  control, marker, command or rung 5. The advisory scores `A:H` only.
- Cheapest next experiment: build pinned vulnerable uhttpd + libubox with ASan,
  set `ubus_prefix=/ubus`, start on a plant-started 127.0.0.1 listener with a
  local rpcd (or null-SID stub), send the one POST and observe the live OOB
  read; then a bounded grooming probe for attacker-influenced source bytes and
  a steerable destination. Fixed pin, TABLE `params` and a bearer token are
  controls.
- Full stage: `reports/frontier-uhttpd2shell.md`.

No witness replay has been requested yet.
