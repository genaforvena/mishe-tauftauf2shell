#!/bin/bash
# Generate the two pinned ms_kill() bodies verbatim from the fetched sources.
# Vulnerable: pins/m_kill.vuln.c lines 170-280 (parent 7bc7e34).
# Fixed:      pins/m_kill.fixed.c lines 170-284 (fix 2ea1382).
set -eu
cd "$(dirname "$0")"
awk 'NR>=170 && NR<=280' ../pins/m_kill.vuln.c >pinned_vuln.h
awk 'NR>=170 && NR<=284' ../pins/m_kill.fixed.c >pinned_fixed.h
printf 'pinned_vuln.h   %s\n' "$(sha256sum pinned_vuln.h | cut -d' ' -f1)"
printf 'pinned_fixed.h  %s\n' "$(sha256sum pinned_fixed.h | cut -d' ' -f1)"
