#!/bin/bash
# Live loopback THeader/ZLIB replay: vulnerable attack, fixed control, safe control.
# All sockets are 127.0.0.1. No external host is contacted.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p results

run_case() {
  local label="$1" serverbin="$2" clientmode="$3" port="$4"
  rm -f "results/${label}-server.log" "results/${label}-client.log"
  ASAN_OPTIONS=detect_leaks=0 timeout 8 "$serverbin" server "$port" \
    >"results/${label}-server.log" 2>&1 &
  local spid=$!
  sleep 1
  ASAN_OPTIONS=detect_leaks=0 timeout 6 ./live-vuln "$clientmode" "$port" \
    >"results/${label}-client.log" 2>&1
  local crc=$?
  wait "$spid"
  local src=$?
  echo "CASE=$label CLIENT_RC=$crc SERVER_RC=$src"
  echo "  client: $(tr '\n' ' ' < "results/${label}-client.log")"
  echo "  server first lines: $(sed -n '1,5p' "results/${label}-server.log" | tr '\n' ' ')"
}

echo "SOURCE_SHA_VULN=$(sha256sum thrift-0.23.0/lib/cpp/src/thrift/transport/THeaderTransport.cpp)"
echo "PIN_SHA_VULN=$(sha256sum ../src/THeaderTransport.cpp.v0.23.0)"
echo "SOURCE_SHA_FIXED=$(sha256sum thrift-0.24.0/lib/cpp/src/thrift/transport/THeaderTransport.cpp)"
echo "PIN_SHA_FIXED=$(sha256sum ../src/THeaderTransport.cpp.v0.24.0)"

run_case vuln-attack ./live-vuln client 29381
run_case fixed-attack ./live-fixed client 29382
run_case vuln-safe ./live-vuln client-safe 29383
