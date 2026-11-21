# Libnxml2Shell frontier harness — provenance

All work 2026-11-21 23:24–23:31Z, loopback only. No external probes; GitHub
fetches below are read-only provisioning. Nothing here is an admission or a
witness verdict.

## Pins

`src/SHA256SUMS` (3/3 OK at 23:30Z):
- `libnxml-0.18.5.tar.gz` — tag `0.18.5` = `9272d1cd6fee…` (affected)
- `libnxml-0.18.6.tar.gz` — tag `0.18.6` = `a1b63cf1db05…` (fixed)
- `fix-fbac242.patch` — upstream fix `fbac242374883edf2ec14127ca6d2accf4704b6a`

Tags resolved via `https://api.github.com/repos/bakulf/libnxml/git/ref/tags/<tag>`;
tarballs from `https://github.com/bakulf/libnxml/archive/refs/tags/<tag>.tar.gz`.

## Build (both pinned trees)

```
cd lab/frontier/libnxml/build
mkdir -p libnxml-0.18.5 libnxml-0.18.6
tar xzf ../src/libnxml-0.18.5.tar.gz -C libnxml-0.18.5 --strip-components=1
tar xzf ../src/libnxml-0.18.6.tar.gz -C libnxml-0.18.6 --strip-components=1
# in each tree:
autoreconf -fi
CC=clang CFLAGS='-g -O0 -fsanitize=address -fno-omit-frame-pointer' \
  LDFLAGS='-fsanitize=address' ./configure --disable-shared --enable-static
make -j4
```

A plain non-ASan 0.18.5 tree (`libnxml-0.18.5-plain`, CFLAGS
`-g -O0 -fno-omit-frame-pointer`) is used only for the gdb layout measurement,
because ASan changes stack layout.

## Run

```
cd lab/frontier/libnxml
clang -g -O0 -fsanitize=address -fno-omit-frame-pointer \
  -Ibuild/libnxml-0.18.5/src -o harness/bin/name_overflow-0.18.5 \
  harness/name_overflow.c build/libnxml-0.18.5/src/.libs/libnxml.a -lcurl
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0
for m in 0 1 2 3 4; do
  ./harness/bin/name_overflow-0.18.5 1022 $m   # vulnerable
  ./harness/bin/name_overflow-0.18.6 1022 $m   # fixed control
  ./harness/bin/name_overflow-0.18.5 1000 $m   # safe-input control
done
```

Modes 0–4 reach the five name-copy loops: element name, close tag, attribute,
DOCTYPE, ENTITY. Raw outputs are `harness/v185-*.out`, `v186-*.out`.

Non-ASan layout, one mode at a time (line/buffer from the ASan trace):

```
gdb -q -batch -x harness/layout.py \
  -ex 'break nxml_parser.c:942 if i == 1022' -ex 'run 1022 0' \
  -ex 'showlayout str' --args ./harness/bin/name_overflow-plain 1022 0
```

Lines: 942 `str` (get_tag), 839 `str` (close), 195 `attr` (get_attr),
521 `str` (doctype), 419 `name` (entity). Outputs: `harness/gdb-layout-m*.out`.
