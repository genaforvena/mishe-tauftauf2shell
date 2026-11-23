#!/usr/bin/env bash
# Provision and build the two pinned libvips trees used by run.sh.
# Provisioning sources are local (gitignored); no external fetch at run time.
set -eu
cd "$(dirname "$0")/.." || exit 1

if [ ! -d src/libvips-8.18.2/libvips ]; then
	echo "MISSING pinned source tree: src/libvips-8.18.2" >&2
	exit 2
fi

if [ ! -d src/libvips-fixed/libvips ]; then
	rm -rf src/libvips-fixed
	cp -a src/libvips-8.18.2 src/libvips-fixed
	cp src/image.c.fixed src/libvips-fixed/libvips/iofuncs/image.c
fi

FLAGS="--buildtype=debug -Db_sanitize=address -Ddeprecated=false
-Dexamples=false -Dcplusplus=false -Dintrospection=disabled
-Dmodules=disabled -Ddocs=false -Dtiff=enabled -Dpng=disabled
-Dwebp=disabled -Dpoppler=disabled"

for pair in "build-vuln-asan src/libvips-8.18.2" \
            "build-fixed-asan src/libvips-fixed"; do
	set -- $pair
	build=$1 src=$2
	if [ ! -f "$build/build.ninja" ]; then
		# shellcheck disable=SC2086
		meson setup "$build" "$src" $FLAGS > "cfg-${build}.log" 2>&1
	fi
	ninja -C "$build" -j2 > "${build}.log" 2>&1
	echo "BUILT $build rc=$?"
done
