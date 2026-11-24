#!/usr/bin/env bash
# Offline verification of the provisioned source pins (no network at run time).
set -euo pipefail
cd "$(dirname "$0")"
sha256sum -c PINS.sha256
bash harness/gen.sh
