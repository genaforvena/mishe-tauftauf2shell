#!/bin/bash
# One-command replay of every solanum2shell claim lane, loopback only.
# Lane 1: verbatim pinned bodies (18 checks). Lane 2: real ircd ASan S2S KILL
# controls (6 checks) against the installed builds at
# /tmp/solanum-{vuln,fixed}-install. Build recipe for those installs is in
# PROVENANCE.md "Real ircd build and loopback S2S KILL".
set -u
root=$(cd "$(dirname "$0")" && pwd) || exit 2
for prefix in /tmp/solanum-vuln-install /tmp/solanum-fixed-install; do
  if [ ! -x "$prefix/bin/solanum" ]; then
    echo "MISSING $prefix/bin/solanum — build both ASan installs first (PROVENANCE.md:71-79)"
    exit 2
  fi
done
bash "$root/harness/run-all.sh" || exit 1
bash "$root/live/run-controls.sh"
