#!/bin/bash
# Build real connmand objects from the pinned tag-2.0 source for
# CVE-2026-115863 / GHSA-725f-6r9j-c4hf.  Everything is provisioned under
# this directory: dev .debs are downloaded and extracted, never installed on
# the host.  The pinned tree under lab/frontier/connman2shell/src is copied
# and never modified; its hashes are asserted on every run.
set -eu
cd "$(dirname "$0")"
E=evidence
mkdir -p "$E" deps/prefix
PIN=../../frontier/connman2shell/src

sha256sum -c >/dev/null <<EOF
722cccc072d658f6c9fded507e1deab8cd8a8837479c9215c88a4834f81fcb0f  $PIN/client-2.0.c
d252cf019c960a3a9a60501429155cead2876269c79ab1cca7443b787f3c5c0e  $PIN/client-2.0-fixed.c
2ff01d8b8d8347fad8876092035a3acfc38fb9048b2ea0da8be90c43af73eada  $PIN/common-2.0.c
EOF

# Provision dev headers/libs into a lab-local prefix. xtables.pc hardcodes
# prefix=/usr, so the explicit -I<prefix>/usr/include below is required too.
(
  cd deps
  for p in libdbus-1-dev libdbus-1-3 libmnl-dev libmnl0 \
           libxtables-dev libxtables12 libnftnl-dev libnftnl11; do
    compgen -G "${p}_*.deb" >/dev/null || apt-get download "$p"
  done
  for f in *.deb; do dpkg-deb -x "$f" prefix; done
)

if [ ! -x deps/connman-buildsrc/configure ]; then
  cp -a "$PIN/connman-2.0" deps/connman-buildsrc
  ( cd deps/connman-buildsrc && autoreconf -fi >../../evidence/autoreconf.log 2>&1 )
fi

if [ ! -f deps/connman-fixedsrc/gdhcp/client.c ]; then
  cp -a deps/connman-buildsrc deps/connman-fixedsrc
  cp "$PIN/client-2.0-fixed.c" deps/connman-fixedsrc/gdhcp/client.c
fi
sha256sum -c >/dev/null <<EOF
d252cf019c960a3a9a60501429155cead2876269c79ab1cca7443b787f3c5c0e  deps/connman-fixedsrc/gdhcp/client.c
EOF

ROOT=$PWD
P=$ROOT/deps/prefix
PC=$P/usr/lib/x86_64-linux-gnu/pkgconfig
INCS="-I$P/usr/include -I$P/usr/include/dbus-1.0 -I$P/usr/lib/x86_64-linux-gnu/dbus-1.0/include"
LIBS="-L$P/usr/lib/x86_64-linux-gnu -Wl,-rpath,$P/usr/lib/x86_64-linux-gnu"

build() {
  name=$1 src=$2 extra=$3
  b=build-$name
  mkdir -p "$b"
  ( cd "$b"
    PKG_CONFIG_PATH=$PC CFLAGS="$extra $INCS" LDFLAGS="$extra $LIBS" \
      "$ROOT/deps/$src/configure" >"../evidence/configure-$name.log" 2>&1
    PKG_CONFIG_PATH=$PC make -j2 >"../evidence/make-$name.log" 2>&1
  )
  test -x "$b/src/connmand"
  printf 'BUILT %-12s %s bytes  sha256=%s\n' "$name" \
    "$(stat -c%s "$b/src/connmand")" \
    "$(sha256sum "$b/src/connmand" | cut -d' ' -f1)"
}

# Plain -O2 build is the production geometry (stack protector visible in
# objdump).  ASan variants use the same pinned sources for the read-side trap.
build plain  connman-buildsrc    ''
build asan   connman-buildsrc    '-fsanitize=address -g -fno-omit-frame-pointer'
build fixed  connman-fixedsrc    '-fsanitize=address -g -fno-omit-frame-pointer'

objdump -d --disassemble=get_domains build-plain/src/connmand \
  >evidence/geometry-plain.txt
grep -E 'strncpy|sub .*rsp|fs:0x28|movb.*0x2e' evidence/geometry-plain.txt \
  >evidence/geometry-summary.txt
printf 'OK realobj build\n'
