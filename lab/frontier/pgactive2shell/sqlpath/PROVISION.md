# pgactive2shell SQL-path laboratory provisioning

Nothing here installs packages system-wide or contacts any target. The
PostgreSQL 16.15 binaries and server headers are public Ubuntu packages
downloaded into `/tmp` and extracted there; loops bind only to 127.0.0.1
and a private Unix socket inside this directory. Ports 58417 and 58418 are
chosen to avoid collision with other plants' loopback services; override
`PORT` if they are taken.

```sh
cd /tmp && mkdir -p pgactive-build && cd pgactive-build
apt-get download postgresql-16 postgresql-client-16 postgresql-server-dev-16
mkdir -p pg16root
for d in *.deb; do dpkg-deb -x "$d" pg16root; done
cd $REPO/lab/frontier/pgactive2shell/sqlpath
sh run.sh          # plain backend: safe + attack, vulnerable + fixed controls
sh run-asan.sh     # ASan-preloaded backend: same controls, live ASan report
```

`parser.c` contains the v2.1.9 and v2.1.10 `pgactive_parse_replident_name`
function bodies and the pinned SQL wrapper, copied verbatim from
`../provision/` and the pinned v2.1.9 release tarball. The scaffolding is
only the PostgreSQL module macro, two export declarations, and type and
constant macros from the pinned headers and PG16 headers. This is **not** a
full pgactive build: no replication worker, no pgactive SQL migration and
no replication wire path are present.

`run.sh` reuses one cluster: the vulnerable SQL call writes past
`NameData` but PostgreSQL's `elog(ERROR)` longjmp bypasses the stack-canary
check, so the plain backend survives and reports a normal SQL error. The
fixed library rejects the same name with its own error message. `run-asan.sh`
preloads libasan into the postmaster; the vulnerable call faults the backend
during `sscanf`, and the fixed control runs in a restarted cluster with its
own library. Logs and client outputs are in `evidence/`.

Observed failure during development, preserved because it explains a false
negative: an early fixed-control run reused the vulnerable function because
the `DROP FUNCTION` step was missing, and the fixed control also crashed
under ASan. Restoring the drop and adding `ON_ERROR_STOP=1` to psql fixed
the control; the final run shows `ASAN_FIXED_SETUP=0`,
`ASAN_FIXED_ATTACK_PSQL_RC=1` (SQL rejection) and `FIXED_SERVER_CLEAN`.
