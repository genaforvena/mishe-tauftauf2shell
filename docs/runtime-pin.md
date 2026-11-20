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

## The seven fork changes

1. **Unit marker** (`units.py`): `# m2shell-generated: …` — each plant's
   sync/doctor scan is blind to the others' unit files in the shared
   `~/.config/systemd/user`.
2. **Duty manifest** (`duties.json`): this plant's own one-duty manifest
   (`dispatch`, resolved by `operator`), identical to the repository's
   copy.
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

## Consequences

- Upgrades mean: take a newer upstream release snapshot, re-apply the
  seven changes above, re-point `runtime/current`, run the full-flag
  sync, and check `mishe doctor` exits 0 before releasing the hold.
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
- The site-local verified binaries (`bin/mishe-tape`, `mishe-records`,
  `mishe-signal-*`) are byte-identical copies of the upstream plant's
  installed framer binaries, with their `*.install.json` sha256 records
  intact.
