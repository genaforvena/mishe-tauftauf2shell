# Frontier brief — open62541 TransferSubscriptions UAF (next local candidate)

**Status: ADMITTED 2026-11-21 ~17:5xZ by the operator under standing approval
#6 (similar-things mandate), no re-ask; independent witness replay delivered
2026-11-21 by the witness (DM #1066): exact 8 PASS trace, raw ASan frames, no repair owed.**
Rungs 1/2/3 ESTABLISHED on verbatim-pinned open62541 1.5.4 under ASan:
`heap-use-after-free`, `WRITE of size 8` at pinned `ua_subscription.c:1645` in
`UA_MonitoredItem_unregisterSampling`, reached through real service calls on
real server/session/subscription/monitored-item objects. Tagged fixed 1.5.6
runs the same sequence clean with the sampling backpointer migrated into the
new subscription. The wake-2 grooming probe observed the stale write landing on
a live replacement object at byte 200; the wake-3 dereference probe then
observed the server's real sampling loop deterministically dereferencing that
attacker-influenced pointer. Rung 4 stays INSTRUMENTED: no chosen bytes,
attacker-chosen control-flow diversion or execution. The dedicated
two-pane window (inner socket index 64), seed wall and registry entry were
pre-created by frontier before admission. Operator admission replay ~17:49Z:
4/4 committed pins OK, 8 PASS / 0 FAIL rc 0, exact trace below. Replay
`bash run.sh /tmp/oa-replay2`: 8 PASS / 0 FAIL, trace
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
- **Rung 4 — INSTRUMENTED, live pointer overwrite plus downstream dereference
  observed.** The wake-2 probes show the stale write landing on a live
  replacement subscription at byte 200: with one item the head is zeroed, with
  two items it is replaced by a live pointer to a monitored item owned by a
  different subscription. The wake-3 probe shows the server's real
  `sampleAndPublishCallback` dereferencing that groomed pointer and enqueuing a
  notification from it, deterministically, with clean skip-delete and fixed
  1.5.6 controls. The written value is a live object pointer selected by the
  create/transfer/delete sequence, not attacker-chosen bytes; no chosen-value
  control, diversion to attacker-chosen code or execution was observed. The ZDI
  RCE language stays a claim, not a lab observation.
- **Tractability — MEDIUM.** Exact fixed tag and a nine-line fix hunk make the
  differential cheap to reason about; producing the authenticated UAF sequence
  needs a configured server and client, not just a single malformed packet.

## Grooming probe: live-neighbour overwrite (open625412shell wake 2)

`lab/frontier/open625412shell/groom_harness.c`, `groom2_harness.c` and `groom.sh`
extend the same
real-service-call sequence: after the delayed free, a second
`Service_CreateSubscription` requests a replacement, then the stale monitored
item is deleted. `bash run.sh <outdir> && bash groom.sh <outdir>` compiles the
probe against both pinned ASan trees and runs six cases. Verified trace
`sha256=c9413debe7063af6287dc2478c5dac8a9204d62f501a35d3ad6eddbb3917660c`
(runner rc 0, raw logs under `<outdir>/groom/`).

Observed on 1.5.4: `sizeof(UA_Subscription)=352`,
`offset(samplingMonitoredItems)=200`; old and replacement subscriptions share
address `0x51300004d040` (`same_chunk=1`), while the replacement's monitored
item `0x514000000640` is a distinct object (`aliased_with_old_mon=0`). Before
the stale delete the replacement's sampling head is `0x514000000640` with one
item; after it the head is `(nil)` with zero items (`changed=1`), and the
process exits 0 because the chunk is allocated, not freed. The skip-delete
control and fixed 1.5.6 both keep the head and one item (`changed=0`, rc 0).

**Conditions and limits.** ASan's quarantine must be disabled
(`quarantine_size_mb=0`) for same-chunk recycling; this is a lab condition, not
a default allocator state. The forced internal delete stand-in and permissive
consent hook from the main harness remain. The value written at byte 200 is
NULL because the transferred sampling list holds one item; no attacker-chosen
bytes or pointer values were demonstrated. A further `UA_Server_run_iterate`
after the write aborts in `UA_MonitoredItem_ensureQueueSpace`
(`ua_subscription.c:1490`) on the *old* monitored item `0x514000000440`; the
same run with the stale delete skipped exits 0. That assertion is recorded as
a downstream observation, not claimed as pointer control or as caused by the
head overwrite.

**Two-item variant: non-NULL pointer overwrite.** `groom2_harness.c` creates two
PUBLISH-sampled items on the old subscription and deletes the list head, so the
stale `LIST_REMOVE` writes the surviving item's address into the reclaimed
subscription. On 1.5.4 the replacement head changes from its own item
`0x514000000840` to `0x514000000440`; that item is owned by the still-live
transferred subscription `0x51300004d200` (`crossSubscription=1`), while the
replacement is `0x51300004d040`. Fixed 1.5.6 keeps head `0x514000000840`,
owner `0x51300004d040` (`crossSubscription=0`). Both runs exit 0 without ASan
reports. This is a live pointer overwrite with a value selected from objects
the sequence created, not arbitrary bytes. Enabling further sampling after the
write sometimes aborts in `UA_MonitoredItem_ensureQueueSpace:1490` and sometimes
survives; that nondeterministic observation is not claimed as control-flow
control. Raw logs: `<outdir>/groom/vuln2.log` and `fixed2.log`.


Pinned-code check (1.5.4 `ua_subscription.c:599-652`): `sendStatusChangeDelete`
calls the same `UA_Subscription_delete` in both branches — `:610` when no
response is queued (BAD status only), and `:652` after sending a status-change
response when `pre` exists (`:642` requires `sub->session->channel`, which an
in-process session lacks). Queuing a real client PublishRequest through
`Service_Publish` (`ua_services_subscription.c:376` → `UA_Session_queuePublishReq`,
`ua_session.c:258`) therefore does not change the memory operation the harness
already performs; it only adds response delivery. That proposed next step is
recorded as a negative result, not an owed experiment. The remaining rung-4
question is a configuration where the stale write stores attacker-chosen bytes
(or a pointer whose downstream dereference changes control flow) in a live object.

## Downstream dereference probe (open625412shell wake 3)

`lab/frontier/open625412shell/deref_harness.c` and `deref.sh` extend the two-item
groom with one client-configured parameter (`requestedParameters.queueSize = 10`,
an ordinary OPC UA client setting that only prevents an unrelated queue-overflow
assertion from preempting the observation) and one lab isolation step
(`Subscription_setState(transferredSub, UA_SUBSCRIPTIONSTATE_REMOVING)` stops the
transferred subscription's sampling callback so only the replacement's callback
runs). No library source is patched; the sink, event loop and both builds are
the verbatim pinned trees.

`bash run.sh <outdir> && bash deref.sh <outdir>`: 14 PASS / 0 FAIL, rc 0, trace
`sha256=0f2a2d7e0a4ca63a15593e3e5cb1f4dde81746e718c0306adb30fa1c839931f3`.
On 1.5.4 with `quarantine_size_mb=0` the freed chunk is reclaimed
(`same_chunk=1`); the stale write sets the replacement's byte-200 head to the
groomed pointer `0x514000000440`, whose owner is the still-live transferred
subscription. With the transferred callback stopped, the replacement's real
`sampleAndPublishCallback` samples the groomed item: its current queue length
rises 4 -> 5 across the paced sampling loop. Skip-delete and fixed 1.5.6 keep
the replacement's own item at the head and the groomed queue at 4 -> 4.

gdb on the same vulnerable binary (conditional breakpoint
`ua_subscription.c:1017 if sub->subscriptionId == 2`) gives frame 0
`sampleAndPublishCallback (sub=0x51300004d040)` calling
`UA_MonitoredItem_sample(server, mon=0x514000000440)`, with
`mon->subscription=0x51300004d200` (a different subscription), under the real
timer/event-loop frames (`processEntryCallback` -> `UA_Timer_process`). The
attacker-influenced pointer is therefore dereferenced by the server's own
sampling loop, not merely read back by the harness.

**Conditions and limits.** ASan quarantine is disabled for same-chunk recycling;
the consent hook and internal-delete stand-ins from earlier wakes remain; the
queue-size setting and callback isolation are lab conditions documented above.
The written value is a live monitored-item pointer whose selection follows the
client's create/transfer/delete ordering, not arbitrary bytes. No chosen-value
control, diversion to attacker-chosen code or execution was observed; rung 4
remains INSTRUMENTED. Raw logs:
`<outdir>/deref/{vuln,control,fixed,gdb-deref}.log`.
Also recorded, not claimed as pointer control: with the default queue size of 1
and sampling enabled, the two-item build aborts deterministically 5/5 at
`UA_MonitoredItem_ensureQueueSpace:1490` on the separately deleted item
`0x514000000640`, while skip-delete and fixed 1.5.6 survive 3/3 each; that
assertion is an availability observation, not control-flow control.

## What would change my mind

An ASan write-after-free at the pinned `LIST_REMOVE` through a real
`TransferSubscriptions` service call would establish rungs 1–3; chosen bytes
through the stale backpointer into a live neighbour would open rung 4.
