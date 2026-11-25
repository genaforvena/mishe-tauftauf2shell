#!/bin/sh
# One-command author replay of the W18 repeated-injection claim: the same
# crafted RR pattern, re-injected at the probe cadence, holds three distinct
# reply-chosen octets across many consecutive 127/8 loopback probes.
# Delegates all source-hash checks and three rebuilds to replay-pattern.sh.
set -u
cd "$(dirname "$0")" || exit 1
D=evidence/w18-repeat TAGPREFIX=w18-replay \
COUNT=${COUNT:-14} GAP=${GAP:-1.0} MIN_HITS=${MIN_HITS:-3} \
    sh replay-pattern.sh || exit 1
echo "REPLAY_PATTERN_REPEAT_OK: 3 stages, count=${COUNT:-14} gap=${GAP:-1.0} min-hits=${MIN_HITS:-3}"
