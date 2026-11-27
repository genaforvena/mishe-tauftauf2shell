#!/bin/sh
# Invoked as RUBY2SHELL_ONIGMO_RUBY by the wire driver; gdb becomes the driver's
# direct child so the driver's health/readiness probes still observe the same
# process tree. All watch output lands in <tag>.server.log via the driver.
set -eu
if [ -n "${RUBY2SHELL_ONIGMO_NOTIMEOUT_RB:-}" ]; then
  RUBYOPT="-r$RUBY2SHELL_ONIGMO_NOTIMEOUT_RB${RUBYOPT:+ $RUBYOPT}"
  export RUBYOPT
fi
exec gdb -q -batch -x "$RUBY2SHELL_ONIGMO_GDB_SCRIPT" --args \
  "$RUBY2SHELL_ONIGMO_GDB_RUBY" "$@"
