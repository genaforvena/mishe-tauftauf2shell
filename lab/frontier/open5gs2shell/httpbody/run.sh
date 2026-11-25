#!/bin/sh
# Source-bound check for the W2 framing question: real v2.8.0 SBI HTTP layers
# copy request bodies verbatim, and parse_multipart() skips exactly one CRLF.
# Offline: uses only pinned sources and the existing realcaller harness.
set -u
cd "$(dirname "$0")/.." || exit 1
mkdir -p httpbody/evidence
PASS=0
FAIL=0
check() {
    if [ "$2" -eq 0 ]; then PASS=$((PASS+1)); echo "PASS-$1"; else FAIL=$((FAIL+1)); echo "FAIL-$1"; fi
}

sha256sum -c pins.sha256 >httpbody/evidence/pins.out 2>&1
check 01-pins-exact "$?"

grep -Fq 'memcpy(request->http.content + offset, data, len);' \
    httpbody/provision/nghttp2-server-v2.8.0.c
check 02-nghttp2-body-copied-verbatim "$?"

grep -Fq 'memcpy(request->http.content + offset, upload_data, *upload_data_size);' \
    httpbody/provision/mhd-server-v2.8.0.c
check 03-mhd-body-copied-verbatim "$?"

grep -Fq 'preamble = 2;' provision/message-v2.8.0.c
check 04-one-leading-crlf-consumed "$?"

grep -Fq 'http->content+preamble, http->content_length-preamble' \
    provision/message-v2.8.0.c
check 05-parser-gets-post-preamble-slice "$?"

grep -Fq 'parse_multipart(message, http);' provision/message-v2.8.0.c
check 06-content-type-dispatches-to-multipart "$?"

{
    echo '=== nghttp2-server-v2.8.0.c:1538-1611'
    awk 'NR>=1538 && NR<=1611 { printf "%5d %s\n", NR, $0 }' \
        httpbody/provision/nghttp2-server-v2.8.0.c
    echo '=== mhd-server-v2.8.0.c:639-681'
    awk 'NR>=639 && NR<=681 { printf "%5d %s\n", NR, $0 }' \
        httpbody/provision/mhd-server-v2.8.0.c
    echo '=== message-v2.8.0.c:3356-3381'
    awk 'NR>=3356 && NR<=3381 { printf "%5d %s\n", NR, $0 }' \
        provision/message-v2.8.0.c
} >httpbody/evidence/source-excerpts.out

sh realcaller/run.sh >httpbody/evidence/realcaller.out 2>&1
RC=$?
check 07-realcaller-chain-runs "$RC"
grep -q 'BODY_LEN=396' httpbody/evidence/realcaller.out
grep -q 'BOUNDARY_LEN=0 BOUNDARY=' httpbody/evidence/realcaller.out
grep -q 'RESULT 15 PASS / 0 FAIL' httpbody/evidence/realcaller.out
check 08-wire-framing-reaches-sink "$?"

echo "RESULT $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
