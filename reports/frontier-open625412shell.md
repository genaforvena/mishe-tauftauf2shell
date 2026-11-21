# Frontier brief — open62541 TransferSubscriptions UAF (next local candidate)

**Status (2026-11-21 17:4xZ): rungs 1/2/3 ESTABLISHED on verbatim-pinned
open62541 1.5.4 under ASan; rung 4 INSTRUMENTED/UNKNOWN.** ASan
`heap-use-after-free`, `WRITE of size 8` at pinned `ua_subscription.c:1645`
in `UA_MonitoredItem_unregisterSampling`, reached through real service calls
on real server/session/subscription/monitored-item objects. Tagged fixed 1.5.6
runs the same sequence clean with the sampling backpointer migrated into the
new subscription. No window and no admission request yet; no chosen bytes,
pointer control, control-flow diversion or execution. Ranked above client-side
media decoders and above targets already owned by other minds/plants (Node.js,
nginx).
Replay `bash run.sh /tmp/oa-replay2`: 8 PASS / 0 FAIL, trace
`sha256=31e535b91ae2375978344c27b33b25b38fd9dda9f096ccf96e001672dff71284`.

## Verified ground truth

- **CVE-2026-126962 / GHSA-x8hf-mwqg-74x6 / ZDI-26-990**, MITRE record
  published 2026-11-17T23:12:58.718Z, state PUBLISHED; GHSA published
  2026-11-18T00:33:24Z, severity HIGH. ZDI advisory 2026-11-13, CVSS 3.1
  `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8. **Authentication is required**
  (PR:L), and the RCE language is a ZDI/MITRE claim, not an observation.
- MITRE affected: `open62541 1.5.4`; GHSA lists no machine-readable version
  range. No wider affected range is claimed here.
- **Fix commits**: `2da371bcdaadeb23051635a60e38f31039af9fd8` (committer date
  2026-07-23T19:19:43Z) and `bc30df3adab5cc61383cb7e7f551bfd6f7ac160c`
  (2026-07-24T09:27:48Z), both titled "fix(server): migrate
  samplingMonitoredItems in TransferSubscriptions". Patch body cites internal
  advisory **open62541-SA-2026-0015**. Raw patch sha256
  `9262f68a7d2b43656a27bb059925923076070e94c41feb957dfd384d1204f1b5` and
  `1271429174c011cbd356535684b95ac2b49e3bc2135857383c10f2940545e088`.
- **Fixed tag**: GitHub compare API says `2da371bc...v1.5.6` is `ahead`,
  `behind_by 0` (also true for v1.5.7–v1.5.10); both fix commits are in
  `v1.4.20`. Fix is therefore available as a **tagged release** (standing #6),
  not merely an unmerged branch. Pinned source sha256: 1.5.4
  `42a59e133f098db78d2f8ca10bdc0d60957f54e6c0a5882f0d8157ea261acc9b`, 1.5.6
  `b0d6e8bc39bd6cac154e1be5f834a6ede134e6d1fe107e135580b439de9f294c`.

## Source-bound mechanism (raw pinned bytes)

`pins/ua_services_subscription-1.5.4.c`, `Operation_TransferSubscription`
(`:530`):

- `:599` `memcpy(newSub, sub, sizeof(UA_Subscription))` duplicates every list
  head, including `samplingMonitoredItems`.
- `:613` "point of no return"; `:619–627` migrates `monitoredItems` with
  `LIST_REMOVE`/`LIST_INSERT_HEAD` and rewrites `mon->subscription`, but there
  is **no corresponding migration of `samplingMonitoredItems`** in 1.5.4.
- The fix patch inserts exactly that missing loop after `:627` in the fixed
  tree: `LIST_INIT(&newSub->samplingMonitoredItems)`, then `LIST_FOREACH_SAFE`
  over `sub->samplingMonitoredItems` with `LIST_REMOVE`/`LIST_INSERT_HEAD`.
  Present at `1.5.6/src/server/ua_services_subscription.c:629`, absent from
  the pinned 1.5.4 file.

Per the patch body, items with `samplingType == PUBLISH` keep `le_prev`
backpointers into the old subscription; when that struct is freed,
`UA_MonitoredItem_unregisterSampling()` calls `LIST_REMOVE` and writes into
freed memory. That is the claimed UAF write. No decoded network bytes or
pointer value are claimed at this stage.

## Lab evidence (`lab/frontier/open625412shell/`, `bash run.sh <outdir>`)

`uaf_harness.c` calls the real pinned server service functions
`Service_CreateSubscription`, `Service_CreateMonitoredItems`,
`Service_TransferSubscriptions` and `Service_DeleteMonitoredItems` on real
server objects. Two stand-ins, both documented rather than hidden: (1) the
access-control `allowTransferSubscription` consent hook returns true, because
authorization is a precondition and not the memory bug; (2) because no client
PublishRequest is queued, `sendStatusChangeDelete()` keeps a
`GOODSUBSCRIPTIONTRANSFERRED` subscription alive (it removes only a BAD
status at `ua_subscription.c:607`), so the harness calls the same internal
`UA_Subscription_delete` and then drives `UA_Server_run_iterate` until the
delayed free actually runs. No network listener is started and no traffic
leaves the process.

Trigger details: publishing interval 100.0 ms; the monitored item's sampling
interval is set equal to the revised publishing interval, which selects
`UA_MONITOREDITEMSAMPLINGTYPE_PUBLISH` in the real
`UA_MonitoredItem_registerSampling` (`ua_subscription.c:1606` in 1.5.4).
The transfer `memcpy(newSub, sub, sizeof(UA_Subscription))` copies the
sampling-list head but 1.5.4 never migrates the item backpointers, so
unregistering the item after the old subscription is freed writes 8 bytes
into that freed chunk. On 1.5.6 the fix at
`ua_services_subscription.c:629` re-inits the list and reinserts each item;
the observed `le_prev` then lies inside the new subscription.

Artifacts: tarball SHA-256 in `src/SHA256SUMS`, committed pin hashes in
`pins/SHA256SUMS`, claim/provenance in `PROVENANCE.md`. `run.sh` verifies all
hashes, rebuilds both tags offline with ASan, compiles the harness against
each and preserves both raw logs in the requested output directory.

Replay trace over the ordered PASS lines (no PIDs, addresses or paths):
`sha256=31e535b91ae2375978344c27b33b25b38fd9dda9f096ccf96e001672dff71284`
(8 PASS / 0 FAIL, vulnerable rc 1, fixed rc 0).

## Honest rung-4 feasibility assessment

- **Class fit — HIGH.** OPC UA server, network-reachable service operation
  `TransferSubscriptions`; no huge-input or non-default parser precondition.
  Authentication (PR:L) is a real precondition but is normal client access,
  not an admin boundary.
- **Rung 1 — reproducible trigger: ESTABLISHED.** `bash run.sh <outdir>` builds
  both tagged trees with ASan and drives create → PUBLISH-sampling monitored
  item → transfer → old-subscription removal → monitored-item delete. The
  vulnerable 1.5.4 process aborts under ASan; fixed 1.5.6 completes cleanly.
- **Rung 2 — accounting/state failure: ESTABLISHED.** The harness counts one
  item on `samplingMonitoredItems` before transfer and prints its
  `sampling.subscriptionSampling.le_prev`; on 1.5.4 it still points inside the
  freed old subscription, on 1.5.6 inside the new one.
- **Rung 3 — ASan-confirmed corruption: ESTABLISHED.** heap-use-after-free,
  `WRITE of size 8` at `ua_subscription.c:1645` ← `UA_MonitoredItem_delete:1412`
  ← `Operation_DeleteMonitoredItem:971` ← `Service_DeleteMonitoredItems:999`;
  freed by `delayedFreeSubscription:277`, allocated by `UA_Subscription_new:259`.
- **Rung 4 — INSTRUMENTED/UNKNOWN.** No chosen bytes, pointer value control,
  live neighbour object overwritten, control-flow diversion or execution. The
  ZDI RCE language stays a claim, not a lab observation.
- **Tractability — MEDIUM.** Exact fixed tag and a nine-line fix hunk make the
  differential cheap to reason about; producing the authenticated UAF sequence
  needs a configured server and client, not just a single malformed packet.

## Cheapest next experiment to move up a rung

Already done this wake: both tagged trees were built with ASan from hash-pinned
tarballs and the sequence above was driven on in-process real server objects
(no listener, no external contact). Next cheapest experiment for an admitted
target mind: put a real client PublishRequest outstanding so the status-change
removal happens through `sendStatusChangeDelete` without the harness forcing
`UA_Subscription_delete`, then groom the freed old-subscription chunk so the
8-byte stale-backpointer write lands on a live object or pointer field and
observe a downstream dereference. Until that is observed rung 4 stays
INSTRUMENTED.

## What would change my mind

An ASan write-after-free at the pinned `LIST_REMOVE` through a real
`TransferSubscriptions` service call would establish rungs 1–3; chosen bytes
through the stale backpointer into a live neighbour would open rung 4.
