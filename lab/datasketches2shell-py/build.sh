#!/usr/bin/env bash
# Verify all pins, extract pinned sources, build three CPython extension
# modules from the UNMODIFIED shipped hll_wrapper.cpp: 5.2.0 plain, 5.3.0
# fixed control, and 5.2.0 under ASan. No network access is required.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
PIN="$HERE/../frontier/datasketches2shell/src"
WORK="$HERE/work"
mkdir -p "$WORK"

(cd "$PIN" && sha256sum -c SHA256SUMS) > "$WORK/pins-library.log" 2>&1 || { cat "$WORK/pins-library.log"; exit 2; }
(cd "$HERE/src" && sha256sum -c SHA256SUMS) > "$WORK/pins-bindings.log" 2>&1 || { cat "$WORK/pins-bindings.log"; exit 2; }

rm -rf "$WORK/datasketches-python-5.2.0" "$WORK/datasketches-cpp-5.2.0" \
  "$WORK/datasketches-cpp-5.3.0" "$WORK/pydeps" "$WORK/build52" "$WORK/build53" \
  "$WORK/buildasan" "$WORK/seedgen" "$WORK/seed.bin"
tar -xzf "$HERE/src/datasketches-python-5.2.0.tar.gz" -C "$WORK" || exit 2
tar -xzf "$PIN/5.2.0.tar.gz" -C "$WORK" || exit 2
tar -xzf "$PIN/5.3.0.tar.gz" -C "$WORK" || exit 2
python3 -m pip install --disable-pip-version-check --no-index \
  --find-links "$HERE/src" --target "$WORK/pydeps" nanobind==3.1.0 \
  > "$WORK/pip.log" 2>&1 || { cat "$WORK/pip.log"; exit 2; }
export PYTHONPATH="$WORK/pydeps${PYTHONPATH:+:$PYTHONPATH}"

I52="-I$WORK/datasketches-cpp-5.2.0/hll/include -I$WORK/datasketches-cpp-5.2.0/common/include"
g++ -std=c++11 -O0 -g $I52 "$HERE/seedgen.cpp" -o "$WORK/seedgen" || exit 2
"$WORK/seedgen" "$WORK/seed.bin" || exit 2

PY=$(command -v python3)
cmake -S "$HERE" -B "$WORK/build52" -DPython_EXECUTABLE="$PY" \
  -DCMAKE_BUILD_TYPE=Debug -DDS2_LIBVER=5.2.0 -DDS2_MODULE=_ds2hll \
  -DDS2_MINI=mini52.cpp > "$WORK/cmake52.log" 2>&1 || { tail -30 "$WORK/cmake52.log"; exit 2; }
cmake --build "$WORK/build52" -j4 > "$WORK/make52.log" 2>&1 || { tail -30 "$WORK/make52.log"; exit 2; }

cmake -S "$HERE" -B "$WORK/build53" -DPython_EXECUTABLE="$PY" \
  -DCMAKE_BUILD_TYPE=Debug -DDS2_LIBVER=5.3.0 -DDS2_MODULE=_ds2hll53 \
  -DDS2_MINI=mini53.cpp > "$WORK/cmake53.log" 2>&1 || { tail -30 "$WORK/cmake53.log"; exit 2; }
cmake --build "$WORK/build53" -j4 > "$WORK/make53.log" 2>&1 || { tail -30 "$WORK/make53.log"; exit 2; }

cmake -S "$HERE" -B "$WORK/buildasan" -DPython_EXECUTABLE="$PY" \
  -DCMAKE_BUILD_TYPE=Debug -DDS2_LIBVER=5.2.0 -DDS2_MODULE=_ds2hllasan \
  -DDS2_MINI=miniasan.cpp -DDS2_ASAN=ON > "$WORK/cmakeasan.log" 2>&1 || { tail -30 "$WORK/cmakeasan.log"; exit 2; }
cmake --build "$WORK/buildasan" -j4 > "$WORK/makeasan.log" 2>&1 || { tail -30 "$WORK/makeasan.log"; exit 2; }

echo "PY_BUILD_OK library_pins=$(wc -l < "$WORK/pins-library.log") binding_pins=$(wc -l < "$WORK/pins-bindings.log") seed=$(stat -c %s "$WORK/seed.bin")"
