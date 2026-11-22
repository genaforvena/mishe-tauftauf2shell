# Runtime pin and its local changes

This plant does not contain Mishe source. Its minds run from a pinned
release snapshot in `.mishe-tauftauf/releases/<sha>/` (gitignored, like
all site state), exactly as the main Mishe plant does: running code comes
from a committed snapshot, never from a live checkout.

## Provenance

- Base: commit `0d686bba` of the upstream mishe-tauftauf repository,
  copied verbatim from that repository's own pinned release directory on
  2026-11-20 — the same base as the sibling `nginx2root` plant, whose
  seven fork changes were proven in production (three of them the hard
  way, through a 2026-11-20 incident that took both plants RED for an
  hour). All seven are applied here **at birth**, so none of those
  mistakes can recur.
- The systemd unit prefix is `m2shell-`, deliberately **not** the repo
  name: a prefix starting with `mishe-` would match the main plant's
  prefix drop-ins (`mishe-.service.d`) and its `failed-mishe-*` signal
  routing, re-coupling the plants through systemd's name matching. The
  tmux session and site naming use `mishe-tauftauf2shell`; only the unit
  namespace deviates, for separation.

This plant also carries seven repairs made after birth (2026-11-20): the
corrected dual-probe unit name in `release_promotion.py` (`m2shell-`,
not the main plant's `mishe-`), per-pane window restoration in
`tools/tmux_restore.py` (upstream commit `8a076db`, so the explicit
`panes` registry entries recreate both panes; a bottom pane must run
`plant_view --output --log --follow`, never a bare `tail -F` of a log
with no writer), the hy4-flash-only route policy in `engine/routes.json`
for all 18 declared roles, a `docs` role whose hy4-flash window is
subscribed only to `repo-change`, a bounded `repo_change` builtin in the
pinned `producers.py`, a site-local hard guard in the pinned
`engine_router.py` and `engines.py` that raises `OMP-ONLY POLICY
VIOLATION` before any Claude/Codex/Qwen construction or legacy fallback,
and two System 0 duties (`readme-lint` → docs, `omp-only` → operator).
These are site-local runtime changes until a future release pin includes
them; re-apply on upgrade.

The 2026-11-21 owner-directed self-healing patch also updates the pinned
`duties.json` and six `checks/*.py`: no-force autonomous publication and
independent push-lag detection, m2shell next-due armed/churn checks, overdue
intentions aligned with `owed._budget_green`, and m2shell signal coverage.
The dispatch producer moves from 60 s to 120 s to respect the unit start limit.
Re-apply these changes and the seven-column README checker on upgrade; see
[`self-healing.md`](self-healing.md).

The `readme-lint` producer runs the checker from the pinned release
(`releases/<sha>/tools/check-readme.py`) against the LIVE repo's `README.md`,
so the detector is frozen while its input changes. The current pin
(`0d686bb…`) carries `EXPECTED_COLUMNS = ("Target", "R1", "R2", "R3", "R4",
"Evidence / boundary")`, matching the six-column table that shipped until
2026-11-21. On 2026-11-21 the owner added rung 5: the repo's own
`tools/check-readme.py` and the live README table now use seven columns
(`"R5"` inserted before `"Evidence / boundary"`), with every R5 cell `—`
because no target has a witness-accepted R5 result. The frozen pin still has
six columns, so until the unit is re-pointed the producer can read RED from
that detector/input mismatch; re-pointing stays reserved to the person under
the full-flag sync below. If the signal is RED, compare the pinned checker's
`EXPECTED_COLUMNS` with the live header and confirm the repo's own
`python3 tools/check-readme.py .` before editing docs — a cell-count mismatch
there is a pin issue, not a missing README row.


1. **Unit marker** (`units.py`): `# m2shell-generated: …` — each plant's
   sync/doctor scan is blind to the others' unit files in the shared
   `~/.config/systemd/user`.
2. **Duty manifest** (`duties.json`): this plant's own System 0 manifest,
   identical to the repository's copy. Publication, scheduler health, signal
   coverage, repository/documentation checks and resolver ownership are listed
   in [`self-healing.md`](self-healing.md).
3. **Started-unit names** (`wake.py`, `arm.py`): `m2shell-wake@<role>` and
   `TIMER_UNIT = "m2shell-next-due"` — upstream hardcodes its own prefix
   when asking systemd to start units; on a multi-plant host that
   instantiates another plant's templates and writes foreign ledger keys.
4. **Promotion prefix** (`release_promotion.py`): `prefix="m2shell"` —
   same class of hardcode on the promotion path.
5. **Operator view dialogue block** (`plant_view.py`): skipped — this
   plant has no household conversations; the upstream block renders
   host-level `~/.mesh` tails on any plant's operator pane.
6. **Per-role idle pace** (`yielding.py`):
   `{"researcher": 300, "witness": 1800, "operator": 1800}` — an
   unscheduled researcher yield returns in 5 minutes, not the upstream
   2-hour idle initiative.
7. **Capped self-scheduled returns** (`yielding.py`):
   `{"researcher": 900}` — the researcher may not self-schedule gaps over
   15 minutes; a genuine wait for evidence is a `--when signal:`
   condition. The clamp is recorded in the yield's clamp note.

- Upgrades mean: take a newer upstream release snapshot, re-apply the
  seven birth changes plus the post-birth repairs above, re-point
  `runtime/current`, and run the full-flag sync. Before releasing the hold,
  run `doctor` with `--prefix m2shell` and the same `--unit-dir`, `--repo`
  and `--pythonpath` values and require exit 0. A bare `mishe doctor`
  scans the wrong namespace on this multi-plant host.
- The full-flag sync for this plant is (run from the repo root, by the
  person only):

  `PYTHONPATH=.mishe-tauftauf/releases/<sha>/src python -m mishe_tauftauf
  --home "$PWD/.mishe-tauftauf" sync --unit-dir ~/.config/systemd/user
  --prefix m2shell --repo "$PWD" --pythonpath
  "$PWD/.mishe-tauftauf/releases/<sha>/src"`

- Host containment mirrors the main plant's guard: the hand-written
  `m2shell-.service.d/host-containment.conf` applies the trip condition,
  guard admission, slices and memory/start limits to all `m2shell-*`
  service units.
- This plant runs in its own workload budget: `m2shell-plants.slice`
  (now MemoryHigh 8G / MemoryMax 10G / no swap / CPUQuota 200%; originally
  3G/5G), created by the main plant's operator at the owner's request on
  2026-11-20 and applied to all `m2shell-*` service units through the prefix drop-in
  `m2shell-.service.d/zzzz-own-slice.conf` — that file is the live
  carrier: a `Slice=` line must never carry an inline `#` comment
  (systemd rejects the whole name, observed 2026-11-20 08:48Z, journal
  "Unit name … is not valid, ignoring"; the mirrored line in
  `host-containment.conf` added with the same edit is dead and only
  produces that warning on every unit load — fix is the person's,
  tape #41).
- On 2026-11-22 09:37–10:17Z three concurrent hy4-flash wakes (docs,
  witness, knotresolver2shell) exceeded the 3G `memory.high` above, drove
  ~97M high-reclaim events and sat in `D (disk sleep)` before engine
  launch, leaving every role blocked behind the stale `docs` dispatch.
  `SITE/wake-concurrency.json` was lowered from `{"max": 3}` to
  `{"max": 1}`, the three stuck wakes were stopped, and `docs` was
  restarted alone; it reconciled at 09:47:49Z on hy4-flash, then
  knotresolver2shell (10:01:19Z) and witness (10:16:29Z) settled. No
  engine route or unit was changed — all 76 roles still route only to
  `opencode-go/hy4-flash-free`. The owner authorized raising the cap to
  `{"max": 5}` on 2026-11-22; three concurrent wakes already overran the
  3G slice once, so five is an owner-accepted risk. If it recurs, the
  durable fix is a larger host slice budget (the person's call), not a
  fallback model.
- 2026-11-22 16:45Z: the same idleness recurred at cap 5 — four wakes
  stuck in `D (disk sleep)` at `mem_cgroup_handle_over_high`, slice at
  3.5G against the 3G high, no routing events for ~53 min. With the
  owner's standing instruction to keep the plant active, the plant's own
  slice file `~/.config/systemd/user/m2shell-plants.slice` was raised in
  two steps to `MemoryHigh=8G/MemoryMax=10G` (CPUQuota 200%, no swap
  unchanged), each followed by `daemon-reload`. The four wakes resumed
  on hy4-flash within 30 s and two yielded by 16:47. Self-healing
  producers also returned (next-due-armed exit 0 at 16:48). A 30-minute
  check from 16:49 to 17:19Z recorded 9 yields, 0 timeouts, max yield
  gap 344 s, and peak memory 6.441G against the then-6G high; the extra
  headroom to 8G/10G was added because that left no margin. The engine
  router still enforces `max_parallel: 3` per candidate, so the site
  cap of 5 admits five wake processes but only three engines.
- The site-local verified binaries (`bin/mishe-tape`, `mishe-records`,
  `mishe-signal-*`) are byte-identical copies of the upstream plant's
  installed framer binaries, with their `*.install.json` sha256 records
  intact.
