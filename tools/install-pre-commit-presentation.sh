#!/bin/sh
# Install tools/pre-commit-presentation.sh as this checkout's pre-commit hook (symlink).
# Refuses to replace a pre-commit hook it did not install.
set -eu

root=$(git rev-parse --show-toplevel)
src="$root/tools/pre-commit-presentation.sh"
dst="$(git rev-parse --git-path hooks)/pre-commit"
case "$dst" in /*) ;; *) dst="$root/$dst" ;; esac

[ -x "$src" ] || chmod +x "$src"

if [ -e "$dst" ] || [ -L "$dst" ]; then
	if [ "$(readlink -f "$dst" 2>/dev/null || true)" != "$(readlink -f "$src" 2>/dev/null || true)" ]; then
		echo "refusing: $dst exists and is not this hook" >&2
		exit 1
	fi
else
	mkdir -p "$(dirname "$dst")"
fi

ln -sfn "$src" "$dst"
echo "installed: $dst -> $src"
