#!/bin/sh
# Pre-commit hook body: keep the generated presentation in sync with the manifest.
# Installed as .git/hooks/pre-commit by tools/install-pre-commit-presentation.sh (symlink).
# Runs only when research-manifest.json is staged; re-renders README.md,
# docs/results.md and docs/assets/evidence-ladder.svg from it and stages those
# files, so a commit cannot carry a front page rendered from an older manifest.
set -eu

root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
if ! git -C "$root" diff --cached --name-only --diff-filter=ACMR -- research-manifest.json | grep -q .; then
	exit 0
fi

renderer="$root/tools/render-presentation.py"
if [ ! -f "$renderer" ]; then
	echo "pre-commit: missing $renderer" >&2
	exit 1
fi
if ! python3 "$renderer" >/dev/null; then
	echo "pre-commit: render-presentation.py failed; commit aborted" >&2
	exit 1
fi
git -C "$root" add -- README.md docs/results.md docs/assets/evidence-ladder.svg
exit 0
