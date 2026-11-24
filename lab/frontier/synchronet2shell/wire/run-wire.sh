#!/usr/bin/env bash
# Real loopback SSH pty-req TERM -> real cryptlib getter -> pinned field layout.
# All network activity is to 127.0.0.1 only.
set -uo pipefail
cd "$(dirname "$0")"
ROOT=../src-tree/3rdp/src/cl
gcc -g -O0 -I"$ROOT" ssh_server.c "$ROOT/libcl.a" -lpthread -o ssh_server 2>&1 || exit 2

term_len=${1:-64}
term=$(python3 -c "print('T' * $term_len, end='')")
out="evidence/wire-term-$term_len.out"
: > "$out"

./ssh_server > "$out" 2>&1 &
server_pid=$!
sleep 1
TERM="$term" timeout 15 ssh -tt \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o PreferredAuthentications=none -o PubkeyAuthentication=no \
  -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
  -o HostKeyAlgorithms=+ssh-rsa -o ConnectTimeout=5 \
  -p 22222 lab@127.0.0.1 true > "evidence/ssh-client-$term_len.out" 2>&1
echo "ssh_rc=$?" >> "$out"
wait "$server_pid" 2>/dev/null
echo "server_rc=$?" >> "$out"
cat "$out"
