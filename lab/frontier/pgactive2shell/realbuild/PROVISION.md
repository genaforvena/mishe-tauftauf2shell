# Full pinned pgactive extension build and loopback SQL path

Everything here uses the pinned release tarballs in `../provision/` and public
Ubuntu packages extracted under `/tmp`. No system-wide install, no external
target, no other node. The cluster binds 127.0.0.1 and a private socket in this
directory; ports used are 58421 (plain) and 58422 (ASan).

## Provisioning observed on this host

```sh
cd /tmp && mkdir -p pgactive-build && cd pgactive-build
apt-get download postgresql-16 postgresql-client-16 postgresql-server-dev-16 \
  libkrb5-dev krb5-multidev libxslt1-dev
mkdir -p pg16root
for d in postgresql-*.deb libkrb5-dev*.deb krb5-multidev*.deb libxslt1-dev*.deb; do
  dpkg-deb -x "$d" pg16root
done
# libpq-fe.h and pqexpbuffer.h live in the system libpq/server-dev headers;
# the extracted pg_config include path alone does not find them.
# Broken symlink targets in the extracted tree need their versioned targets:
cp /usr/lib/x86_64-linux-gnu/libgssapi_krb5.so.2.2 pg16root/usr/lib/x86_64-linux-gnu/
cp /usr/lib/x86_64-linux-gnu/libxslt.so.1.1.39 pg16root/usr/lib/x86_64-linux-gnu/
```

`pg_config` is at
`/tmp/pgactive-build/pg16root/usr/lib/postgresql/16/bin/pg_config`
(not `usr/bin/pg_config`); PGXS is at
`/tmp/pgactive-build/pg16root/usr/lib/postgresql/16/lib/pgxs/src/makefiles/pgxs.mk`.
LLVM bitcode generation fails because this host has no `clang-17`, so all
builds pass `with_llvm=no`; this does not affect the server shared library.

## Build both pinned releases

```sh
for V in 2.1.9 2.1.10; do
  mkdir -p /tmp/pgactive-full-$V
  tar xzf /home/mesh-home/mishe-tauftauf2shell/lab/frontier/pgactive2shell/provision/pgactive-$V.tar.gz \
      -C /tmp/pgactive-full-$V
  cd /tmp/pgactive-full-$V/pgactive-$V
  PG_CONFIG=/tmp/pgactive-build/pg16root/usr/lib/postgresql/16/bin/pg_config \
      ./configure
  make -j4 with_llvm=no \
      EXTRA_CFLAGS='-I/usr/include/postgresql -I/usr/include/postgresql/internal -I/tmp/pgactive-build/pg16root/usr/include'
done
```

Observed 2026-11-25: 2.1.9 `make` rc 0 with `pgactive.so`, `pgactive_dump`
and `pgactive_init_copy`; 2.1.10's `pg_dump` compat file needs
`ATTRIBUTE_VERSION_ATTOPTION` absent from PG16.15 headers, so its helper
binaries do not build — `make pgactive.so with_llvm=no ...` alone succeeds and
is sufficient for the parser control. Install 2.1.9 with `make install`; copy
`pgactive--2.1.10*.sql` from its source tree into the extension share
directory for the fixed control, and swap `pgactive.so` between the two builds
between runs (restore 2.1.9 afterwards).

## Runs

```sh
sh run-real.sh                                  # full 2.1.9 extension
VERSION=2.1.10 LABEL=fixed sh run-real.sh       # full 2.1.10 control
sh run-real-asan.sh                             # ASan-instrumented 2.1.9
```

`run-real.sh` starts the cluster with `shared_preload_libraries=pgactive`,
`track_commit_timestamp=on` and `wal_level=logical` (required by `_PG_init`),
creates the extension at the requested version, and calls the schema-qualified
`pgactive.pgactive_parse_replident_name(text)` with a safe name and with
`pgactive_123_1_2_3_` plus 80 `AZ` bytes. `run-real-asan.sh` rebuilds only the
shared library with `-fsanitize=address`, preloads libasan into the postmaster,
and restores the normal installed library on exit. All clusters are stopped by
the scripts; no cluster is left running.

## Observed results (2026-11-25 02:21Z)

- 2.1.9: `CREATE_vuln=0`, safe call returns the parsed row, attack reports
  `ERROR: could not parse slot name: ...` (`elog(ERROR)` longjmp bypasses the
  stack canary), zero backend terminations. `evidence/vuln-*.out`.
- 2.1.10: `CREATE_fixed=0`, same safe row, attack reports
  `ERROR: could not parse replication origin name: ...`, zero terminations.
  `evidence/fixed-*.out`.
- Function ACL in both fresh installs is
  `{"\"mesh-home\"=X/\"mesh-home\""}` — no PUBLIC EXECUTE in *either*
  version. The 2.1.9 fresh-install SQL already contains
  `REVOKE ALL ON FUNCTION pgactive_parse_replident_name(text) FROM public`;
  the fix is the parser format, not a newly introduced revoke. A caller still
  needs owner/granted execute or a different reachable path, consistent with
  the advisory's authenticated `PR:L` precondition.
- ASan-instrumented full extension: `WRITE of size 161` at offset 96 of
  `[32, 96) 'replication_name' (line 349)`, frames
  `pgactive_parse_replident_name src/pgactive_catalogs.c:351` and
  `pgactive_parse_replident_name_sql src/pgactive.c:1531`, from the SQL
  statement logged in `evidence/real-asan-server.log`. Client rc 2, backend
  faulted, `ASAN_STOP=0`, normal library restored. This is rung 3 through the
  real extension, not rung 5: no saved pointer/IP, no replication wire path,
  no command side effect.
