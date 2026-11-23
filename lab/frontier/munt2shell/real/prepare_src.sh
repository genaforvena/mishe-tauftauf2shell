#!/bin/sh
# Regenerate real/{src/vuln-2_8_3,src/fixed-1749f7f} from the provisioned
# pinned tarball and pins/fix.patch. Nothing in src/ is committed; both trees
# are disposable and this script is safe to rerun. Verifies the tarball hash,
# every pin, and the three pinned files in each regenerated tree.
#
# Usage: ./prepare_src.sh [path-to-tarball]
# Default tarball: src/munt-libmt32emu_2_8_3.tar.gz (gitignored).
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(dirname "$HERE")
TARBALL=${1:-$HERE/src/munt-libmt32emu_2_8_3.tar.gz}
EXPECTED_TARBALL=81f8c462f46bc8901618762ae34cf9de93894ff81f41db73c79472fa3baef875

die() { echo "prepare_src.sh: $*" >&2; exit 1; }
hash_of() { sha256sum "$1" | cut -d ' ' -f 1; }
pin_of() { awk -v key="$1" '$2 == key {print $1}' "$ROOT/PINS.sha256"; }
check_tree() {
	tree=$1
	variant=$2
	for pair in MidiStreamParser.cpp MidiStreamParser.h globals.h; do
		got=$(hash_of "$tree/mt32emu/src/$pair")
		want=$(pin_of "pins/$pair.$variant")
		[ -n "$want" ] || die "no pin for $pair.$variant"
		[ "$got" = "$want" ] || die "$tree: $pair sha256 $got != pinned $want"
	done
	echo "ok $tree: cpp/header/globals match pins/$variant"
}

[ -f "$TARBALL" ] || die "tarball not found: $TARBALL (provision it as in REPLAY.md)"
got=$(hash_of "$TARBALL")
[ "$got" = "$EXPECTED_TARBALL" ] || die "tarball sha256 $got != $EXPECTED_TARBALL"
(cd "$ROOT" && sha256sum -c PINS.sha256 >/dev/null) || die "committed pins do not match PINS.sha256"
echo "ok tarball and committed pins"

mkdir -p "$HERE/src"
tmp=$(mktemp -d "$HERE/src/.prepare.XXXXXX")
trap 'rm -rf "$tmp"' 0 1 2 3 15
tar -xzf "$TARBALL" -C "$tmp"
src="$tmp/munt-libmt32emu_2_8_3"
[ -d "$src/mt32emu/src" ] || die "tarball lacks mt32emu/src"
check_tree "$src" vuln

cp -R "$src" "$tmp/fixed"
(cd "$tmp/fixed" && patch -s -p1 < "$ROOT/pins/fix.patch") || die "pins/fix.patch failed to apply"
check_tree "$tmp/fixed" fixed

rm -rf "$HERE/src/vuln-2_8_3" "$HERE/src/fixed-1749f7f"
mv "$src" "$HERE/src/vuln-2_8_3"
mv "$tmp/fixed" "$HERE/src/fixed-1749f7f"
echo "ready: src/vuln-2_8_3 and src/fixed-1749f7f"
