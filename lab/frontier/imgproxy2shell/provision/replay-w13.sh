#!/bin/sh
# One-command clean-archive replay of the W13 negative.
#
# Usage:
#   sh replay-w13.sh [WORKDIR]                  # WORKDIR defaults to /tmp/w13-replay
#   IMGPROXY_BIN=/path/to/imgproxy-vuln LIBVIPS_LIBDIR=/path/to/libvips \
#     sh replay-w13.sh /tmp/my-w13-replay
#
# Defaults are this plant's gitignored pinned CLI and libvips build; a fresh
# checkout must supply those two paths (they are not committed). The script
# verifies their SHA-256 / the probe hash, extracts only the committed
# imgproxy2shell tree from the pinned commit, and runs the three W13 configs.
# Every listener and request stays on 127.0.0.1 ports 18180/18181. A final
# "REPLAY_W13_OK 3/3 ..." means all three windows had zero code pointers.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${1:-/tmp/w13-replay}
case "$WORK" in /tmp/*) ;; *) echo "REFUSE WORKDIR outside /tmp: $WORK"; exit 2;; esac
COMMIT=2e6b4d16
PROBE_SHA=9c2adf676855265822fa687fb7fa0b1fe9fcc944bd8f045e5b7f273b4b1046bb
BIN_SHA=ea2317df2a42d30e81f33e0cfd822b49b99996545ffc49026573212b03d8165d
BIN=${IMGPROXY_BIN:-$HERE/imgproxy-vuln}
LIBDIR=${LIBVIPS_LIBDIR:-$HERE/../../libvips2shell/build-vuln-plain/libvips}
REPO=$(cd "$HERE/../../../.." && pwd)

die() { printf 'SETUP_FAIL %s\n' "$1"; exit 1; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

[ -f "$HERE/ico_codeptr_reach.py" ] || die "probe script missing"
[ "$(sha "$HERE/ico_codeptr_reach.py")" = "$PROBE_SHA" ] || die "probe hash drift"
[ -f "$BIN" ] || die "pinned imgproxy-vuln missing: $BIN"
[ "$(sha "$BIN")" = "$BIN_SHA" ] || die "binary hash drift"
[ -d "$LIBDIR" ] || die "libvips libdir missing: $LIBDIR"
git -C "$REPO" cat-file -e "${COMMIT}^{commit}" || die "commit $COMMIT absent"

rm -rf "$WORK"
mkdir -p "$WORK" || die "mkdir $WORK"
git -C "$REPO" archive "$COMMIT" lab/frontier/imgproxy2shell | tar -x -C "$WORK" \
  || die "clean archive extract"
DST=$WORK/lab/frontier/imgproxy2shell/provision
ln -s "$BIN" "$DST/imgproxy-vuln" || die "symlink binary"
PASS=0
FAIL=0
for spec in c1:2:1024 c2:6:64 c3:2:256; do
  tag=$(printf 'r%s' "${spec%%:*}")
  rest=${spec#*:}
  preload=${rest%%:*}
  bodylen=${rest##*:}
  out=$(cd "$DST" && python3 ico_codeptr_reach.py ./imgproxy-vuln \
        "$LIBDIR" "$tag" "$preload" "$bodylen" 10 2>&1)
  printf '%s\n' "$out"
  log="$DST/http-ico-w13-$tag.log"
  if printf '%s\n' "$out" | grep -q "W13_CLASSIFY.*code_ptr_qwords=0" &&
     printf '%s\n' "$out" | grep -q "W13_HIT" &&
     printf '%s\n' "$out" | grep -q "W13_END" &&
     [ -f "$log" ]; then
    printf 'PASS %s code_ptr_qwords=0\n' "$tag"
    PASS=$((PASS + 1))
  else
    printf 'FAIL %s\n' "$tag"
    FAIL=$((FAIL + 1))
  fi
done
printf 'W13 replay logs: %s\n' "$DST"
if [ "$FAIL" -eq 0 ]; then
  printf 'REPLAY_W13_OK %s/3 code_ptr_qwords=0\n' "$PASS"
else
  printf 'REPLAY_W13_FAIL %s FAIL\n' "$FAIL"
fi
[ "$FAIL" -eq 0 ]
