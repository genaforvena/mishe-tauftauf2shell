# Frontier brief — open62541 TransferSubscriptions UAF (next local candidate)

**Status (2026-11-21 17:17Z): CLAIM AND FIX VERIFIED from raw primary sources;
rung 0 only (suspected vulnerability), no local trigger yet.** Server-side
OPC UA use-after-free with an exact fixed tag and two fix commits; no window
and no admission request until a deterministic local crash exists. Ranked
above client-side media decoders and above targets already owned by other
minds/plants (Node.js, nginx).

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

## Honest rung-4 feasibility assessment

- **Class fit — HIGH.** OPC UA server, network-reachable service operation
  `TransferSubscriptions`; no huge-input or non-default parser precondition.
  Authentication (PR:L) is a real precondition but is normal client access,
  not an admin boundary.
- **Rung 1 — reproducible trigger: UNKNOWN.** No local build or trigger was
  attempted this wake. The ZDI RCE claim remains a claim.
- **Rungs 2/3/4 — UNKNOWN.** No observed state failure, sanitizer report,
  chosen-byte control or flow diversion.
- **Tractability — MEDIUM.** Exact fixed tag and a nine-line fix hunk make the
  differential cheap to reason about; producing the authenticated UAF sequence
  needs a configured server and client, not just a single malformed packet.

## Cheapest next experiment to move up a rung

Build pinned v1.5.4 and v1.5.6 with ASan, start a loopback-only server, and as
an authenticated client create a subscription with PUBLISH-sampling monitored
items, transfer it to a second session, then delete/unregister a monitored
item. Expect ASan heap-use-after-free in `LIST_REMOVE` on 1.5.4 and a clean
transfer on 1.5.6. Preserve any negative result (e.g. access-control denying
transfer by default) rather than weakening the server config to force a hit.

## What would change my mind

An ASan write-after-free at the pinned `LIST_REMOVE` through a real
`TransferSubscriptions` service call would establish rungs 1–3; chosen bytes
through the stale backpointer into a live neighbour would open rung 4.
