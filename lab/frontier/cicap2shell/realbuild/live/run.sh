#!/bin/sh
# One-request loopback replay against a built c-icap ASan tree.
# Usage: sh run.sh BUILD_DIR PORT LABEL MODE [VALUE] [MAX_REALLOC]
#   BUILD_DIR  e.g. /tmp/cicap-real/build-asan (vulnerable) or build-fixed
#   MODE       attack | safe | valid | options
# Raw server/client output lands in ../evidence/live-LABEL-{server,client}.out
set -eu
BUILD=$1
PORT=$2
LABEL=$3
MODE=$4
VALUE=${5:-90}
REALLOC=${6:-100}
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$HERE/../evidence
mkdir -p "$OUT"
CFG=/tmp/cicap-w3-$LABEL.conf
PIDF=/tmp/cicap-w3-$LABEL.pid
CTL=/tmp/cicap-w3-$LABEL.ctl
rm -f "$PIDF" "$CTL"
cat > "$CFG" <<EOF
PidFile $PIDF
CommandsSocket $CTL
TmpDir /tmp
ServerName cicap-lab-$LABEL
ServerLog /tmp/cicap-w3-$LABEL-server.log
AccessLog /tmp/cicap-w3-$LABEL-access.log
Port 127.0.0.1:$PORT
StartServers 1
MaxServers 1
MaxRequestsReallocateMem $REALLOC
ServicesDir $BUILD/services/echo/.libs
Service echo srv_echo.so
EOF
(cd "$BUILD" && ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
    ./c-icap -N -S -D -f "$CFG") > "$OUT/live-$LABEL-server.out" 2>&1 &
SRV=$!
python3 - "$PORT" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
for _ in range(100):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
        break
    except OSError:
        time.sleep(0.1)
else:
    raise SystemExit("server did not listen on 127.0.0.1:%d" % port)
PY
python3 "$HERE/client.py" "$MODE" "$VALUE" "$PORT" | tee "$OUT/live-$LABEL-client.out"
kill -TERM "$SRV" 2>/dev/null || true
wait "$SRV" 2>/dev/null || true
if grep -q 'AddressSanitizer' "$OUT/live-$LABEL-server.out"; then
    echo "ASAN=YES (details in $OUT/live-$LABEL-server.out)"
else
    echo "ASAN=NO"
fi
