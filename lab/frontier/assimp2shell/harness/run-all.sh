#!/usr/bin/env bash
# Reproduce the whole direct-call matrix and, if built, the real-importer cases.
set -uo pipefail
cd "$(dirname "$0")"
ROOT="$(cd .. && pwd)"
LOG="$ROOT/evidence.log"
: > "$LOG"
log() { printf '%s\n' "$*" | tee -a "$LOG"; }

cd "$ROOT"
log "=== pins $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
sha256sum -c PINS.sha256 2>&1 | tee -a "$LOG" || exit 2
cd harness
./build.sh 2>&1 | tee -a "$LOG" || exit 3

run() {
  local tag="$1"; shift
  log "=== $tag ==="
  local rc
  "$@" >>"$LOG" 2>&1
  rc=$?
  log "rc=$rc"
}

for cc in g++ clang++; do
  for mode in vec4pos vec3idx idx3 safe; do
    for build in vuln fixed; do
      run "direct-$build-$cc-$mode" env ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 "./bin/$build-$cc-asan" "$mode"
    done
  done
done
run direct-vuln-plain-vec4pos ./bin/vuln-plain vec4pos
run direct-vuln-plain-vec3idx ./bin/vuln-plain vec3idx
run direct-fixed-plain-vec4pos ./bin/fixed-plain vec4pos

if [ -x ./bin/real-vuln ]; then
  for case in vec4pos idx3 safe; do
    run "real-vuln-$case" env ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 ./bin/real-vuln "cases/$case.gltf"
  done
fi
if [ -x ./bin/real-fixed ]; then
  for case in vec4pos idx3 safe; do
    run "real-fixed-$case" env ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 ./bin/real-fixed "cases/$case.gltf"
  done
fi

log "=== assertions ==="
fail=0
ck() {
  local tag="$1" pattern="$2" start="$3" end="$4"
  if sed -n "${start},${end}p" "$LOG" | grep -qF -- "$pattern"; then
    log "PASS $tag"
  else
    log "FAIL $tag ($pattern)"
    fail=$((fail+1))
  fi
}
# Locate each case block by its header, then check until the next block.
line_of() { grep -n "^=== $1 ===$" "$LOG" | head -1 | cut -d: -f1; }
next_of() { awk -v s="$1" 'NR>s && /^=== / {print NR; exit}' "$LOG"; }
for tag in direct-vuln-g++-vec4pos direct-vuln-clang++-vec4pos; do
  s=$(line_of "$tag"); e=$(next_of "$s")
  ck "$tag heap" "heap-buffer-overflow" "$s" "$e"
  ck "$tag write16" "WRITE of size 16" "$s" "$e"
  ck "$tag region36" "36-byte region" "$s" "$e"
done
s=$(line_of direct-vuln-g++-vec3idx); e=$(next_of "$s")
ck direct-vec3idx-write12 "WRITE of size 12" "$s" "$e"
s=$(line_of direct-vuln-g++-idx3); e=$(next_of "$s")
ck direct-idx3-stack "stack-buffer-overflow" "$s" "$e"
ck direct-idx3-value "'value'" "$s" "$e"
for tag in direct-fixed-g++-vec4pos direct-fixed-clang++-vec4pos direct-fixed-g++-vec3idx; do
  s=$(line_of "$tag"); e=$(next_of "$s")
  ck "$tag clean" "ok=0" "$s" "$e"
done
s=$(line_of direct-vuln-plain-vec4pos); e=$(next_of "$s")
ck plain-chosen-tauf "54 41 55 46" "$s" "$e"
log "failures=$fail"
log "evidence.log hash recorded in evidence.sha256"
sha256sum "$LOG" > "$ROOT/evidence.sha256"
exit "$fail"
