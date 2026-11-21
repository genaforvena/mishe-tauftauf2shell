#!/usr/bin/env bash
# Reproducible ASan build of the REAL pinned gpfdist.c sources against the
# local shim headers, real libapr-1 1.7.2 and libevent 2.1.
#
# What is real: gpfdist.c, gpfdist_helper.c, every write statement, APR pools,
# libevent and the HTTP parser.  What is shimmed: PostgreSQL's configure-
# generated headers (postgres.h / pg_config*.h) and the WarehousePG fstream
# file-I/O backend (stubbed to always open successfully).  This is NOT a stock
# WarehousePG binary; the report labels it accordingly.
# Provisioning (W65 nit): upstream/gpfdist_helper.c is real 7.6.1-WHPG
# upstream bytes, but .gitignore:88 ignores upstream/, so a clean checkout
# has no helper. Fetch the tag's gpfdist_helper.c into upstream/ before
# building; its bytes must match the 7.6.1-WHPG tag.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
PIN=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/gpfdist2shell/src
cd "$HERE"
for TAG in 7.6.1 7.6.2; do
  gcc -fsanitize=address -fno-omit-frame-pointer -g -O0 -std=gnu11 \
      -I shim -I /usr/include/apr-1.0 \
      -o "gpfdist_v${TAG}_asan" \
      "$PIN/gpfdist_v${TAG}.c" upstream/gpfdist_helper.c fstream_stub.c \
      -levent -lapr-1
  echo "built gpfdist_v${TAG}_asan"
done
