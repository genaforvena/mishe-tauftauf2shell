#!/bin/sh
# Deterministic assertions + normalized trace for the REAL SDL_mixer AIFF lane.
# A crafted AIFF-C file is decoded by an unmodified real SDL_mixer 3.2.4 build
# with the AIFF decoder enabled (vulnerable / fixed / no-stack-protector).
# Trace excludes PIDs, addresses, paths and timing.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT="$HERE/evidence"
mkdir -p "$OUT"
PASS=0; FAIL=0

expect() {
    if grep -qF "$2" "$1"; then PASS=$((PASS+1));
    else FAIL=$((FAIL+1)); printf 'FAIL %s: missing %s\n' "$3" "$2"; fi
}
absent() {
    if grep -qF "$2" "$1"; then FAIL=$((FAIL+1)); printf 'FAIL %s: found %s\n' "$3" "$2";
    else PASS=$((PASS+1)); fi
}
trace() { printf '%s\n' "$1" >> "$OUT/real-trace.txt"; }

export ASAN_SYMBOLIZER_PATH=/usr/lib/llvm-18/bin/llvm-symbolizer
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0

: > "$OUT/real-trace.txt"
: > "$OUT/real-summary.txt"

for d in vuln-asan fixed-asan vuln-nossp; do
  for f in alaw256.aifc ulaw256.aifc alaw8.aifc raw256.aifc pcm8_256.aiff; do
    case "$f" in
      alaw256.aifc|ulaw256.aifc) sc=attack ;;
      *) sc=safe ;;
    esac
    F="$OUT/real-$d-$f-decode.out"
    set +e
    (cd "$OUT" && "./aiff-driver-$d" "$f" decode) > "$F" 2>&1
    RC=$?
    set -e
    printf '%s %s decode rc=%d\n' "$d" "$f" "$RC" >> "$OUT/real-summary.txt"

    if [ "$d" = vuln-asan ] && [ "$sc" = attack ]; then
      expect "$F" 'ERROR: AddressSanitizer: stack-buffer-overflow' "$d-$f"
      expect "$F" 'WRITE of size 4' "$d-$f"
      expect "$F" 'decoder_aiff.c:95:16' "$d-$f"
      expect "$F" 'AIFF_decode' "$d-$f"
      expect "$F" 'MIX_DecodeAudio' "$d-$f"
      expect "$F" "[32, 1056) 'buffer' (line 535)" "$d-$f"
      expect "$F" 'overflows this variable' "$d-$f"
      if [ "$f" = alaw256.aifc ]; then expect "$F" 'FetchALaw' "$d-$f";
      else expect "$F" 'FetchULaw' "$d-$f"; fi
      trace "$d $f ASAN-STACK-WRITE4-AIFF-95-VIA-REAL-MIXER"
    elif [ "$d" = fixed-asan ]; then
      absent "$F" 'AddressSanitizer' "$d-$f"
      expect "$F" 'RESULT=OK' "$d-$f"
      trace "$d $f FIXED-clean-RESULT-OK"
    elif [ "$d" = vuln-nossp ] && [ "$sc" = attack ]; then
      if [ "$RC" -eq 0 ]; then FAIL=$((FAIL+1)); printf 'FAIL %s rc=0\n' "$d-$f";
      else PASS=$((PASS+1)); fi
      trace "$d $f no-stack-protector-nonzero-rc"
    else
      absent "$F" 'AddressSanitizer' "$d-$f"
      expect "$F" 'RESULT=OK' "$d-$f"
      trace "$d $f clean-RESULT-OK"
    fi
  done
done

# Playback path: decode runs on the real SDL audio thread (MIX_PlayTrack).
PF="$OUT/real-play-vuln-asan.out"
set +e
(cd "$OUT" && ./aiff-driver-vuln-asan alaw256.aifc play) > "$PF" 2>&1
PRC=$?
set -e
printf 'vuln-asan alaw256.aifc play rc=%d\n' "$PRC" >> "$OUT/real-summary.txt"
expect "$PF" 'ERROR: AddressSanitizer: stack-buffer-overflow' 'play-asan'
expect "$PF" 'WRITE of size 4' 'play-asan'
expect "$PF" 'thread T1' 'play-thread'
expect "$PF" 'AIFF_decode' 'play-decode'
expect "$PF" 'DecodeMore' 'play-decode'
expect "$PF" 'MixerCallback' 'play-mixer'
trace 'vuln-asan alaw256.aifc play ASAN-WRITE4-ON-AUDIO-THREAD-T1'

QF="$OUT/real-play-fixed-asan.out"
set +e
(cd "$OUT" && ./aiff-driver-fixed-asan alaw256.aifc play) > "$QF" 2>&1
set -e
absent "$QF" 'AddressSanitizer' 'play-fixed'
expect "$QF" 'RESULT=OK' 'play-fixed'
trace 'fixed-asan alaw256.aifc play clean-RESULT-OK'

# Rung 4: real A-law LUT word from a chosen input byte at the first OOB offset.
G="$OUT/gdb-real-chosen-i1.out"
expect "$G" 'HIT length=256 i=1' 'gdb-real-hit'
expect "$G" 'lutword=bae001c0' 'gdb-real-lutword'
expect "$G" '0xc0	0x01	0xe0	0xba' 'gdb-real-stored-bytes'
trace 'gdb real-decoder i=1 buffer+1024 A-law-LUT-word-bae001c0'

HASH=$(sha256sum "$OUT/real-trace.txt" | cut -d' ' -f1)
printf 'PASS=%d FAIL=%d trace=%s\n' "$PASS" "$FAIL" "$HASH"
[ "$FAIL" -eq 0 ]
