#!/usr/bin/env bash
# CONTENT_LENGTH state oracle for CVE-2026-119618.
# Two loopback-only ASan httpd instances: 2.4.70 affected, 2.4.71 fixed.
set -o pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$ROOT/run" "$ROOT/cgi-bin" "$ROOT/htdocs" "$ROOT/logs"
cp "$ROOT/oracle-cgi.sh" "$ROOT/cgi-bin/oracle"
chmod +x "$ROOT/cgi-bin/oracle"
printf 'ok\n' > "$ROOT/htdocs/index.html"

# Modules to load explicitly; MPM event and mod_so are built into httpd here.
MODS="authn_core authz_core authz_host unixd mime log_config logio headers dir alias reqtimeout setenvif filter http2 cgi version"

conf_for() {
  v="$1"; port="$2"
  prefix="$ROOT/install-$v-asan"
  conf="$ROOT/run/httpd-$v.conf"
  {
    printf 'ServerRoot "%s"\n' "$prefix"
    printf 'PidFile "%s/run/httpd-%s.pid"\n' "$ROOT" "$v"
    printf 'Listen 127.0.0.1:%s\n' "$port"
    for m in $MODS; do
      so="$prefix/modules/mod_${m}.so"
      if [ -f "$so" ]; then
        printf 'LoadModule %s_module modules/mod_%s.so\n' "$m" "$m"
      fi
    done
    cat <<EOF
ServerName localhost
ErrorLog "$ROOT/logs/httpd-$v-error.log"
LogLevel info
LogFormat "%h %l %u %t \"%r\" %>s %b" common
CustomLog "$ROOT/logs/httpd-$v-access.log" common
Protocols h2c http/1.1
H2Direct on
H2MaxSessionStreams 100
DocumentRoot "$ROOT/htdocs"
<Directory "$ROOT/htdocs">
    Require all granted
</Directory>
ScriptAlias /cgi-bin/ "$ROOT/cgi-bin/"
<Directory "$ROOT/cgi-bin">
    Require all granted
    Options +ExecCGI
    SetHandler cgi-script
</Directory>
EOF
  } > "$conf"
  printf '%s\n' "$conf"
}

start_one() {
  v="$1"; port="$2"
  prefix="$ROOT/install-$v-asan"
  conf=$(conf_for "$v" "$port")
  pidf="$ROOT/run/httpd-$v.pid"
  echo "== starting $v on 127.0.0.1:$port =="
  ASAN_OPTIONS="detect_leaks=0:halt_on_error=1:log_path=$ROOT/logs/asan-$v" \
  UBSAN_OPTIONS="print_stacktrace=1" \
    "$prefix/bin/httpd" -f "$conf" -DFOREGROUND \
    > "$ROOT/logs/httpd-$v-stdout.log" 2>&1 &
  for i in $(seq 1 60); do
    if curl -sS --max-time 1 -o /dev/null "http://127.0.0.1:$port/index.html" 2>/dev/null; then
      echo "ready $v (pid $(cat "$pidf" 2>/dev/null))"
      return 0
    fi
    sleep 0.25
  done
  echo "FAILED to start $v; see $ROOT/logs/httpd-$v-stdout.log"
  return 1
}

stop_one() {
  v="$1"; pidf="$ROOT/run/httpd-$v.pid"
  if [ -f "$pidf" ]; then
    kill "$(cat "$pidf")" 2>/dev/null
    for i in $(seq 1 40); do [ -f "$pidf" ] || break; sleep 0.1; done
    [ -f "$pidf" ] && kill -9 "$(cat "$pidf")" 2>/dev/null
    rm -f "$pidf"
  fi
}

probe() {
  port="$1"; label="$2"
  echo "--- $label: HEADERS with Content-Type, no Content-Length, END_STREAM ---"
  curl --http2-prior-knowledge -sS --max-time 10 \
    -H 'Content-Type: text/plain' \
    -D "$ROOT/logs/hdr-$label.txt" \
    "http://127.0.0.1:$port/cgi-bin/oracle" 2>&1
  echo "curl_rc=$?"
  echo "response headers:"
  cat "$ROOT/logs/hdr-$label.txt" 2>/dev/null
}

trap 'stop_one 2.4.70; stop_one 2.4.71' EXIT

start_one 2.4.70 7080 || exit 1
probe 7080 2.4.70
stop_one 2.4.70

start_one 2.4.71 7171 || exit 1
probe 7171 2.4.71
stop_one 2.4.71

echo "== ASan/UBSan report files =="
ls -l "$ROOT"/logs/asan-* 2>/dev/null || echo "(none)"
echo "== error-log tails =="
for v in 2.4.70 2.4.71; do echo "--- $v ---"; tail -20 "$ROOT/logs/httpd-$v-error.log" 2>/dev/null; done
