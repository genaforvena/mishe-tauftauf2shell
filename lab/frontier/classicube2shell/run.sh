#!/bin/bash
# Self-checking offline replay for the ClassiCube PNG ASan harness.
# Uses only the committed pins; no network, no loopback service needed.
# Usage: bash run.sh [output-dir]   (default output dir: out/)
set -u
cd "$(dirname "$0")" || exit 2
OUT="${1:-out}"
rm -rf "$OUT"
mkdir -p "$OUT" || exit 2

pass=0
fail=0
ck() {
  local name="$1" got="$2" want="$3"
  if [ "$got" = "$want" ]; then
    pass=$((pass + 1)); echo "PASS $name"
  else
    fail=$((fail + 1)); echo "FAIL $name got=[$got] want=[$want]"
  fi
}

sha() { sha256sum "$1" | cut -d' ' -f1; }

ck "pin:classicube-1.3.9.tar.gz" "$(sha pins/classicube-1.3.9.tar.gz)" \
  "5bb62dbb3ad27e1fbb09842f0cb1f4802b2686553b017e0b67ce09b36f908246"
ck "pin:classicube-1.4.0.tar.gz" "$(sha pins/classicube-1.4.0.tar.gz)" \
  "8f249f435fcce4dac083664c43077073c32c5382a485de3bcd81badf1816143f"
ck "pin:classicube-fix-c461fa7.patch" "$(sha pins/classicube-fix-c461fa7.patch)" \
  "3e0b9b1933ddb8db5cdb33589d3d9cc059c027ce7ed5fa11f13c0d74eb6ba6ba"
ck "pin:Bitmap-1.3.9.c" "$(sha pins/Bitmap-1.3.9.c)" \
  "de9d89d46c9f5d3818fb5d2480ba67831f2c3d96f2c51998d21fa68b6586d5d6"
ck "pin:Bitmap-1.4.0.c" "$(sha pins/Bitmap-1.4.0.c)" \
  "7b37f36ce1b73c105e5a1f873c58c50fc2f5b86e2821a76ca0902b42b93b424c"

python3 gen_inputs.py > "$OUT/gen_inputs.log" 2>&1 || { echo "FAIL gen_inputs"; exit 2; }
sh build.sh > "$OUT/build.log" 2>&1 || { echo "FAIL build"; cat "$OUT/build.log"; exit 2; }
ck "build:asm_139" "$([ -x asm_139 ] && echo yes || echo no)" yes
ck "build:asm_140" "$([ -x asm_140 ] && echo yes || echo no)" yes

declare -A INPUT_SHA=(
  [zero_width_avg.png]=3656c286255070b348acca73285d53918a18b06e2af98bad2612354f54f30697
  [zero_width_paeth.png]=fe513a8c516c4c3803330d5e46fd37fb8642ded8a445e11c37592e15272f77fd
  [dup_ihdr_underflow.png]=63a7a83957165973189a116b1fed25899d6db63de1bb5c513707ddc31f5ba8e2
  [benign.png]=b3cdf2504960934675450572816127d2537226b394521961124a7943fb6808cc
  [benign_avg_paeth.png]=f05488fea9a43bbe3abd424052abbbe5f8d1138109c613c3854df9c84cf80ca8
  [zero_width_h1.png]=1bbd2c800a344dc9e0860fda993d984859a215cb3cf0afa5decb2d0f57478d90
)
for name in "${!INPUT_SHA[@]}"; do
  ck "input:$name" "$(sha "inputs/$name")" "${INPUT_SHA[$name]}"
done

# name | binary | input | expected rc | expected RESULT | expected ASan
run_case() {
  local name="$1" bin="$2" input="$3" xrc="$4" xres="$5" xasan="$6"
  local log="$OUT/$name.out" rc res asan
  set +e
  ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:symbolize=1 \
    "./$bin" "inputs/$input" > "$log" 2>&1
  rc=$?
  ck "$name rc" "$rc" "$xrc"
  res=$(grep -o 'RESULT=0x[0-9A-F]*' "$log" | cut -d= -f2 | head -n 1)
  ck "$name result" "${res:-none}" "$xres"
  if grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' "$log"; then asan=ASAN; else asan=none; fi
  ck "$name asan" "$asan" "$xasan"
}

NONE=none
run_case vuln_zero_width_avg    asm_139 zero_width_avg.png    1 "$NONE"          ASAN
run_case vuln_zero_width_paeth  asm_139 zero_width_paeth.png  1 "$NONE"          ASAN
run_case vuln_dup_ihdr          asm_139 dup_ihdr_underflow.png 1 "$NONE"         ASAN
run_case fixed_zero_width_avg   asm_140 zero_width_avg.png    0 0xCCDED074      none
run_case fixed_zero_width_paeth asm_140 zero_width_paeth.png  0 0xCCDED074      none
run_case fixed_dup_ihdr         asm_140 dup_ihdr_underflow.png 0 0xCCDED075     none
run_case vuln_benign           asm_139 benign.png            0 0x00000000      none
run_case fixed_benign           asm_140 benign.png            0 0x00000000      none
run_case vuln_benign_avg_paeth  asm_139 benign_avg_paeth.png  0 0x00000000      none
run_case fixed_benign_avg_paeth asm_140 benign_avg_paeth.png  0 0x00000000      none
run_case vuln_zero_width_h1     asm_139 zero_width_h1.png     0 0x00000000      none
run_case fixed_zero_width_h1    asm_140 zero_width_h1.png     0 0xCCDED074      none

# Extra raw-byte assertions on the two positive ASan reports. These pin the
# claimed mechanism, not just "an ASan report happened".
grep -q 'WRITE of size 1' "$OUT/vuln_dup_ihdr.out" \
  && ck 'dup write size' yes yes || ck 'dup write size' no yes
grep -q '985 bytes after 15-byte region' "$OUT/vuln_dup_ihdr.out" \
  && ck 'dup underflow offset' yes yes || ck 'dup underflow offset' no yes
grep -q 'Inflate_Process .*Deflate.c:699' "$OUT/vuln_dup_ihdr.out" \
  && ck 'dup sink frame' yes yes || ck 'dup sink frame' no yes
grep -q 'Png_Reconstruct .*Bitmap.c:173' "$OUT/vuln_zero_width_avg.out" \
  && ck 'avg sink frame' yes yes || ck 'avg sink frame' no yes
grep -q 'Png_Reconstruct .*Bitmap.c:183' "$OUT/vuln_zero_width_paeth.out" \
  && ck 'paeth sink frame' yes yes || ck 'paeth sink frame' no yes
grep -q '0 bytes after 2-byte region' "$OUT/vuln_zero_width_avg.out" \
  && ck 'zero-width alloc size' yes yes || ck 'zero-width alloc size' no yes

python3 - "$OUT" <<'PY' > "$OUT/trace.txt"
import hashlib, pathlib, re, sys
out = pathlib.Path(sys.argv[1])
lines = []
for log in sorted(out.glob('*.out')):
    text = log.read_text(errors='replace')
    tag = log.stem
    for pat in (r'ERROR: AddressSanitizer: [a-z-]+',
                r'(?:READ|WRITE) of size \d+',
                r'in (\w+) [^ ]+?/(\w+\.c):(\d+)',
                r'is located \d+ bytes after \d+-byte region',
                r'RESULT=0x[0-9A-F]{8}'):
        for m in re.finditer(pat, text):
            s = m.group(0)
            s = re.sub(r'0x[0-9a-f]+', '0xADDR', s)
            s = re.sub(r'^in (\w+) [^ ]+?/(\w+\.c):(\d+)$', r'\1 \2:\3', s)
            lines.append(f'{tag}|{s}')
print('\n'.join(lines))
PY
TRACE=$(sha256sum "$OUT/trace.txt" | cut -d' ' -f1)
echo "TRACE_SHA256=$TRACE"
echo "PASS_COUNT=$pass FAIL_COUNT=$fail"
[ "$fail" -eq 0 ] || exit 1
