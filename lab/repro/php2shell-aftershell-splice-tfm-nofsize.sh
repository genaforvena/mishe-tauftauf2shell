#!/bin/bash
# php2shell — W71 control wrapper: run the SHA-pinned W70 single-pool harness
# with prlimit(1) neutered, so NO RLIMIT_FSIZE (and no CPU limit) is applied to
# any worker and no phase-2 preload kills the write. This isolates the write
# clamp: if the splice cannot form on the stock pwrite path, the result is a
# bounded negative for stock/default reachability, not a harness failure.
#
# Usage: same arguments as php2shell-aftershell-splice-tfm.sh; recommended
#   GAP=1 ONE_POOL=1 TOKEN_SEED=1 DEATH_MODE=rlimit with fresh attacker bytes.
# The pinned harness is never edited; only the PATH-visible prlimit is a shim.

set -eu
ROOT=$(cd "$(dirname "$(dirname "$(dirname "$(readlink -f "$0")")")")" && pwd)
HARNESS="$ROOT/lab/repro/php2shell-aftershell-splice-tfm.sh"
SHIM=$(mktemp -d)
cleanup() { rm -rf "$SHIM"; }
trap cleanup EXIT
cat > "$SHIM/prlimit" <<'EOF'
#!/bin/bash
# no-op prlimit: report the inherited file-size limit, apply nothing.
if [ "${*: -1}" = "--fsize" ]; then
    echo "max file size              unlimited"
    echo "max file size (soft)       unlimited"
fi
exit 0
EOF
chmod +x "$SHIM/prlimit"
echo "NO_FSIZE wrapper: prlimit neutered via $SHIM/prlimit; inherited ulimit -f: $(ulimit -f)" >&2
echo "NO_FSIZE wrapper: pinned harness sha256 $(sha256sum "$HARNESS" | cut -d' ' -f1)" >&2
export PATH="$SHIM:$PATH"
exec bash "$HARNESS" "$@"
