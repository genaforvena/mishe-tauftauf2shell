#!/usr/bin/env bash
# Replay the loopback telnetd wire experiment. ASan pins: vulnerable long SLC
# suboption must fault in add_slc; fixed 2.8 and a short suboption stay clean.
# Plain build (when present): long suboption segfaults, short survives.
set -euo pipefail
H="$(cd "$(dirname "$0")" && pwd)"
L="$(cd "$H/.." && pwd)"
E="$H/evidence"
mkdir -p "$E"
V="$L/build/asan-2.7/telnetd/telnetd"
F="$L/build/asan-2.8/telnetd/telnetd"
P="$L/build/plain-2.7/telnetd/telnetd"
for bin in "$V" "$F"; do
  [ -x "$bin" ] || { echo "MISSING $bin — build both ASan pins first" >&2; exit 2; }
done

python3 "$H/run_wire.py" --telnetd "$V" --out "$H/vuln-long" --triplets 50 >/dev/null
python3 "$H/run_wire.py" --telnetd "$F" --out "$H/fixed-long" --triplets 50 --no-debug >/dev/null
python3 "$H/run_wire.py" --telnetd "$V" --out "$H/vuln-short" --triplets 5 >/dev/null
cases=(vuln-long fixed-long vuln-short)
if [ -x "$P" ]; then
  python3 "$H/run_wire.py" --telnetd "$P" --out "$H/plain-100" --triplets 100 >/dev/null
  python3 "$H/run_wire.py" --telnetd "$P" --out "$H/plain-short" --triplets 5 >/dev/null
  cases+=(plain-100 plain-short)
fi

norm () {
  sed -E -e 's/==[0-9]+==/==PID==/g' \
         -e 's/0x[0-9a-fA-F]+/0xADDR/g' \
         -e 's/BuildId: [0-9a-f]+/BuildId: ID/g' \
         -e "s|$L|LAB|g" -e "s|$H|WIRE|g" \
         -e 's/^[[:space:]]*#[0-9]+ 0xADDR /#FRAME /' "$1"
}
for c in "${cases[@]}"; do
  norm "$H/$c.daemon.log" > "$E/norm-$c.log"
  norm "$H/$c.summary.txt" \
    | sed -E -e 's/listen=127\.0\.0\.1:[0-9]+/listen=127.0.0.1:PORT/' \
             -e '/^greeting=/d' -e '/^our_bytes_first=/d' \
             -e 's/^our_bytes_len=.*/our_bytes_len=N/' \
             -e 's/^subopts_total=.*/subopts_total=N/' > "$E/norm-$c.summary"
done
sha256sum "$E"/norm-* | sed "s#$E/##" > "$L/WIRE_HASHES.txt"

fail=0
check () { if grep -q "$2" "$1"; then echo "PASS $3"; else echo "FAIL $3"; fail=1; fi; }
check "$E/norm-vuln-long.summary" 'exploit_sent=True' 'vuln long wire payload sent'
check "$E/norm-vuln-long.summary" 'asan_global_overflow=True' 'vuln long ASan global overflow'
check "$E/norm-vuln-long.summary" 'asan_write1=True' 'vuln long WRITE of size 1'
check "$E/norm-vuln-long.summary" 'add_slc_frame=True' 'vuln long add_slc frame'
check "$E/norm-vuln-long.summary" 'daemon_exit=-6' 'vuln long aborted'
for frame in add_slc process_slc do_opt_slc telnetd_run; do
  check "$E/norm-vuln-long.log" "$frame" "wire call chain $frame"
done
if grep -q 'suboption' "$E/norm-vuln-long.log" && grep -q 'telrcv' "$E/norm-vuln-long.log"; then
  echo "PASS wire call chain direct: telrcv -> suboption"
elif grep -q 'deferslc' "$E/norm-vuln-long.log" && grep -q 'defer_terminit' "$E/norm-vuln-long.log"; then
  echo "PASS wire call chain deferred: localstat -> defer_terminit -> deferslc"
else
  echo "FAIL wire call chain (neither direct nor deferred)"; fail=1
fi
check "$E/norm-vuln-long.log" '0 bytes after global variable' '0 bytes past slcbuf'
check "$E/norm-fixed-long.summary" 'asan_error=False' 'fixed 2.8 long ASan clean'
check "$E/norm-fixed-long.summary" 'accepted=True' 'fixed 2.8 accepted LINEMODE'
check "$E/norm-vuln-short.summary" 'asan_error=False' 'vuln short suboption clean'
check "$E/norm-vuln-short.summary" 'accepted=True' 'vuln short accepted LINEMODE'
if [ -x "$P" ]; then
  check "$E/norm-plain-100.summary" 'daemon_exit=-11' 'plain 2.7 long segfault'
  check "$E/norm-plain-short.summary" 'alive_before_terminate=True' 'plain 2.7 short survives'
fi
cat "$L/WIRE_HASHES.txt"
exit "$fail"
