#!/bin/sh
# Re-fetch the upstream files that establish the v4.14.7 1514 -> FIM sink path
# and print the exact chain lines. Read-only provisioning; no target contact.
set -eu
BASE=https://raw.githubusercontent.com/wazuh/wazuh
OUT=trace-src
mkdir -p "$OUT"
fetch() { # tag path localname expected-sha
    if [ ! -f "$OUT/$3" ]; then
        curl -sSf "$BASE/$1/$2" -o "$OUT/$3"
    fi
    got=$(sha256sum "$OUT/$3" | cut -d' ' -f1)
    if [ "$got" != "$4" ]; then
        echo "SHA MISMATCH $3: expected $4 got $got" >&2
        exit 1
    fi
    echo "OK $3 $got"
}
fetch v4.14.7 src/analysisd/analysisd.c src_analysisd_analysisd.c \
    e731ade2672714bad28e8fe35939e0abe658f3389b45185a6aa2f549db5757be
fetch v4.14.7 src/remoted/secure.c v747_secure.c \
    b05af1d212c5a84e2c019c5f12781642b632774e5a82cef049d351b747daa7b5
fetch v4.14.8 src/remoted/secure.c v748_secure.c \
    b05af1d212c5a84e2c019c5f12781642b632774e5a82cef049d351b747daa7b5
fetch v4.14.7 src/headers/mq_op.h mq_op.h \
    84e0c9820d7cc24f27a7144343625370723904536335b5cfdc4998a6bc4eab90
fetch v4.14.8 src/analysisd/analysisd.c v748_analysisd.c \
    58686aac3f38fb298b3e2c6e17ea5b3d7acc9ff901f4e49c0e8f4d8230b7353f
# The pinned harness file must be the same upstream object.
fetch v4.14.7 src/analysisd/decoders/syscheck.c decoders-syscheck.c.v4.14.7 \
    7b3b7c666c5e9dde0d843efb2de37b99b51664bb30b8dda6841e3af8f0f1cadc

echo "--- 1514 framing (secure.c) ---"
grep -n 'SYSCHECK_HEADER \|SendMSG(logr.m_queue' "$OUT/v747_secure.c" | head -8
echo "--- queue tag (mq_op.h) ---"
grep -n 'SECURE_MQ\|SYSCHECK_MQ' "$OUT/mq_op.h" | head -4
echo "--- analysisd dispatch and decode entry ---"
grep -n 'msg\[0\] == SYSCHECK_MQ\|decode_fim_event' "$OUT/src_analysisd_analysisd.c" | head -6
echo "--- decoder to sink (pinned syscheck.c) ---"
grep -n 'cJSON_Parse(lf->log)\|fim_process_alert(sdb\|fim_fetch_attributes(attributes\|snprintf(lf->full_log' "$OUT/decoders-syscheck.c.v4.14.7" | head -8
echo "--- v4.14.8 fixed sink (pinned syscheck.c) ---"
grep -n 'char alert\[OS_MAXSTR\]\|snprintf(alert\|os_strdup(alert' src/syscheck.c.v4.14.8 | head -6
