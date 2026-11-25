#!/bin/sh
# W9: does any LIVE pointer in process_udp's REGISTER_SUPER_NAK case land
# inside the forward overflow window (nak+14 .. nak+14+token_size-1) in a
# different compiler/optimization build? W5 found `peer` register-resident
# in the pinned gcc -O1 build; this script measures the actual stack slots
# at -O0/-O2 for gcc and clang and prints their offsets from &nak.
# Loopback only: each supernode is started by gdb against 127.0.0.1 only.
set -u
HERE=$(cd "$(dirname "$0")" || exit 1; pwd)
N2N=$(cd "$HERE/.." || exit 1; pwd)
TARBALL=$N2N/provision/n2n-vuln.tar.gz
COMMUNITY=$N2N/provision/build/n2n-plain/community.list
SENDER=$HERE/send_nak.py
EVID=$HERE/evidence
WORK=${TMPDIR:-/tmp}/n2n2shell-w9.$$
mkdir -p "$WORK" || exit 1
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
PORT_BASE=${PORT_BASE:-18820}

build() {
    name=$1 cc=$2 opt=$3
    d=$WORK/$name
    mkdir -p "$d" || return 1
    tar xzf "$TARBALL" -C "$d" || return 1
    src=$d/n2n-dc7324af16b2ff3e2b22961e7d8dffcb14f3f6ff
    [ -d "$src" ] || return 1
    cp "$COMMUNITY" "$src/community.list" || return 1
    (cd "$src" && sh autogen.sh &&
        CC="$cc" CFLAGS="-g $opt -fno-omit-frame-pointer" ./configure &&
        make -j4 supernode) >"$WORK/build-$name.log" 2>&1
    [ -x "$src/supernode" ] || return 1
    echo "$src"
}

measure() {
    name=$1 src=$2 port=$3
    cmd=$WORK/gdb-$name.txt
    {
        echo 'set pagination off'
        echo 'set confirm off'
        echo 'break sn_utils.c:2331'
        echo "run -f -p 127.0.0.1:$port -t $((port+1)) -c community.list -F labfed -M"
        echo 'python'
        echo 'import gdb'
        echo 'gdb.write("W9_LAYOUT_BEGIN" + chr(10))'
        echo 'for v in ("nak","peer","encx","nakbuf","sockbuf","mac_buf","sn","cmn","sender","idx","rem","now"):'
        echo '    try:'
        echo '        gdb.write("W9VAR %s %d" % (v, int(gdb.parse_and_eval("&" + v))) + chr(10))'
        echo '    except Exception:'
        echo '        gdb.write("W9VAR %s UNAVAILABLE" % v + chr(10))'
        echo 'gdb.write("W9_LAYOUT_END" + chr(10))'
        echo 'end'
        echo 'kill'
        echo 'quit'
    } >"$cmd"
    (cd "$src" && timeout 25 gdb -q -batch -x "$cmd" ./supernode) \
        >"$EVID/w9-layout-$name.log" 2>&1 &
    gp=$!
    sleep 5
    python3 "$SENDER" "$port" safe >"$EVID/w9-layout-$name-sender.log" 2>&1
    wait "$gp" 2>/dev/null || true
}

for spec in 'gcc-o0 gcc -O0' 'gcc-o2 gcc -O2' 'clang-o0 clang -O0' 'clang-o2 clang -O2'; do
    set -- $spec
    name=$1 cc=$2 opt=$3
    src=$(build "$name" "$cc" "$opt") || { echo "$name BUILD FAIL"; continue; }
    measure "$name" "$src" "$PORT_BASE"
    PORT_BASE=$((PORT_BASE+10))
done
python3 - "$WORK" "$EVID" <<'PY'
import glob, os, re, sys
for path in sorted(glob.glob(os.path.join(sys.argv[1], 'gdb-*.txt'))):
    name = os.path.basename(path)[4:-4]
    log = os.path.join(sys.argv[2], 'w9-layout-' + name + '.log')
    text = open(log, errors='replace').read()
    m = re.search(r'W9_LAYOUT_BEGIN(.*?)W9_LAYOUT_END', text, re.S)
    if not m:
        print(f'{name}: NO LAYOUT (gdb stopped early)')
        continue
    vals = {}
    for line in m.group(1).splitlines():
        q = re.match(r'W9VAR (\S+) (\S+)', line.strip())
        if q and q.group(2) != 'UNAVAILABLE':
            vals[q.group(1)] = int(q.group(2))
    base = vals.get('nak')
    if base is None:
        print(f'{name}: no nak address')
        continue
    out = []
    for key in ('peer','encx','mac_buf','sockbuf','nakbuf','cmn','sender','sn','idx','rem','now'):
        if key in vals:
            out.append(f'{key}={vals[key]-base:+d}')
        else:
            out.append(f'{key}=OPT')
    print(f'{name}: &nak={base:#x} ' + ' '.join(out))
PY
echo "W9 done; raw logs in $EVID/w9-layout-*.log"
