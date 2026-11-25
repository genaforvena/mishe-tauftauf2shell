# Self-healing machinery

The plant uses **System 0 producers** for polling and evidence, **signals** for
edges and expiry, and **minds** for diagnosis and repair. A producer does not
need a model. An author, timer, or Git hook is never its own acceptance signal.

## Duties and owners

`duties.json` is the tracked manifest. Every duty has one resolver and the
resolver is automatically subscribed to its signal.

| Duty | Resolver | What it proves or repairs |
|---|---|---|
| `dispatch` | `operator` | An open wake has not exceeded its bound. |
| `main-publication` | `operator` | Local `main` reaches `origin/main`; performs bounded no-force publication and reconciliation. |
| `push-lag` | `operator` | Independently detects divergence or an unpublished commit older than 15 minutes. |
| `next-due-armed` | `operator` | The next-due record, installation marker, and `m2shell-next-due-*` timer agree. |
| `next-due-churn` | `operator` | The scheduler does not repeatedly replace a pending next-due timer without running its handler. |
| `overdue-intention` | `operator` | Every overdue intention has a later wake or an intentional hold. |
| `signal-coverage` | `operator` | Registered signals have producers and subscribers, declared producers run, and faults receive attention or a recorded disposition. |
| `repo-change` | `docs` | A changed HEAD produces one docs wake with the new commit as evidence. |
| `readme-lint` | `docs` | The landing-page structure and evidence table still parse and link to real reports. |
| `omp-only` | `operator` | Every declared role routes only to an approved OMP model; forbidden engines/models, missing routes and stale engine files are RED. |

The ordinary `failed-m2shell-*.service` signals continue to route a failed
unit to its resolver. The `doctor` and `engine-routing` signals also wake
`operator`.

## Publication and divergence repair

Two independent publication paths exist:

1. `tools/post-commit-push.sh` waits for the commit to settle, then publishes
   it from a transient **`m2shell-push-*`** unit in
   **`m2shell-plants.slice`**. It never uses the main plant's `mishe-*` unit
   namespace or workload slice.
2. `checks/main-publication.py` fetches and publishes from the duty timer, so
   a skipped hook or a killed hook job cannot leave commits stranded.

The fallback only pushes without force. A strict fast-forward needs no new
commit. If a later amend has made local and published `main` diverge, the
publisher:

1. reads the local and fetched remote commits;
2. creates a reconciliation commit with the **local HEAD tree** and **both
   commits as parents**;
3. atomically advances `refs/heads/main` only if HEAD is still the commit it
   read; and
4. performs the ordinary no-force push.

This preserves the published commit in history while keeping the final tree
byte-identical to the newer local tree. It does not rewrite the index or
worktree, force-push, or discard the remote commit. A HEAD race aborts that
attempt safely; the next duty tick retries. If the push fails after the local
reconciliation, the next attempt is a normal fast-forward.

`checks/push-lag.py` is the independent detector over the same property. It
returns RED for divergence or excessive lag and UNKNOWN when the remote cannot
be read. An unreadable remote is never reported as GREEN.

## Signals before and after unit rendering

A signal can be registered and observed directly, which gives `operator` the
edge immediately. Persistent producer timers and all missing target wake paths
are installed only by the **exact full-flag sync** in
[`runtime-pin.md`](runtime-pin.md). A bare `mishe sync` is forbidden on this
multi-plant host. Unit rendering and systemd changes remain person-reserved;
the `m2shell-` prefix is mandatory everywhere.

The checks are standalone Python and can also be run directly for diagnosis:

```sh
python3 checks/push-lag.py --repo "$PWD"
python3 checks/next-due-armed.py --home "$PWD/.mishe-tauftauf"
python3 checks/overdue-intention.py --home "$PWD/.mishe-tauftauf"
python3 checks/signal-coverage.py --home "$PWD/.mishe-tauftauf"
```

`main-publication.py` is intentionally not in that read-only list: running it
may create a reconciliation commit and publish `main`.
