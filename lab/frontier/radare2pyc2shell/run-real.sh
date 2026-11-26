#!/bin/sh
# Replay crafted/safe .pyc through a real ASan-instrumented radare2 rabin2.
# Local only; no network or remote target. Pass the rabin2 binary as $1 or let
# the default point at the 6.1.8 build configured in upstream/.
set -eu

LAB=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
RABIN2=${1:-"$LAB/upstream/radare2-6.1.8/build-asan/binr/rabin2/rabin2"}
OUT="$LAB/out-real"
mkdir -p "$OUT"

if [ ! -x "$RABIN2" ]; then
	printf 'missing rabin2: %s\n' "$RABIN2" >&2
	exit 1
fi

ASAN_OPTIONS=detect_leaks=0:symbolize=1
export ASAN_OPTIONS

for name in safe attack; do
	case "$name" in
		safe) input="$LAB/safe-ascii.pyc" ;;
		attack) input="$LAB/crafted-ascii.pyc" ;;
	esac
	set +e
	"$RABIN2" -s "$input" >"$OUT/$name.stdout" 2>"$OUT/$name.stderr"
	rc=$?
	set -e
	printf '%s RC=%d stderr=%s\n' "$name" "$rc" "$OUT/$name.stderr"
done
