#!/bin/sh
# Generate loopback-only test keys whose UIDs place a chosen byte at the
# offset that becomes status argument byte 1000 in gpg's IMPORTED line.
# No passphrase, no network, no external key material. Requires host gpg.
set -eu
cd "$(dirname "$0")"
here=$PWD
keys=$here/realgpg/keys
mkdir -p "$keys"

gen_key () {
  name=$1; length=$2; marker=$3
  home=$keys/gen-$name
  rm -rf "$home"
  mkdir -p "$home"
  chmod 700 "$home"
  uid=$(python3 - "$length" "$marker" <<'PY'
import sys
length, marker = int(sys.argv[1]), sys.argv[2]
chars = list('A' * length)
# args = "<16-hex-keyid> <uid>"; args[1000] is uid[983] for long UIDs.
if length > 983:
    chars[983] = marker
print(''.join(chars))
PY
)
  GNUPGHOME="$home" gpg --batch --pinentry-mode loopback --passphrase '' \
    --quick-generate-key "$uid <w@example.test>" ed25519 sign 0 \
    >"$keys/gen-$name.log" 2>&1
  GNUPGHOME="$home" gpg --batch --armor --export >"$keys/$name.asc"
  printf 'generated %s uidlen=%s marker=%s sha256=%s\n' "$name" "$length" \
    "$marker" "$(sha256sum "$keys/$name.asc" | cut -d' ' -f1)"
}

gen_key long-H 1200 H
gen_key long-Z 1200 Z
gen_key long-7 1200 7
gen_key short 120 0
echo "KEYS OK"
