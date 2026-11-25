#!/usr/bin/env bash
# Emit the verbatim 3.20b TERM-copy statement and check the shipped layout.
# No copy logic is retyped: vuln320b.inc comes straight from answer-320b.cpp.
set -euo pipefail
cd "$(dirname "$0")"

sha256sum -c PINS.sha256 >/dev/null

# Release identity and the exact field order that the 64-byte write reaches.
grep -F '#define VERSION 	"3.20"' evidence/sbbsdefs-320b.h >/dev/null
grep -F "REVISION	'b'" evidence/sbbsdefs-320b.h >/dev/null
grep -F '#define TELNET_TERM_MAXLEN	40' evidence/telnet-320b.h >/dev/null
grep -A2 'char[[:space:]]*terminal\[' evidence/sbbs-320b.h \
  | grep -F 'int		cterm_version=0;' >/dev/null
grep -A3 'char[[:space:]]*terminal\[' evidence/sbbs-320b.h \
  | grep -F 'link_list_t savedlines{};' >/dev/null
grep -A2 'typedef struct link_list {' evidence/link_list-320b.h \
  | grep -F 'list_node_t*		first;' >/dev/null
grep -A3 'typedef struct link_list {' evidence/link_list-320b.h \
  | grep -F 'list_node_t*		last;' >/dev/null

python3 - <<'PY'
from pathlib import Path
src = Path('evidence/answer-320b.cpp').read_text().splitlines()
# Pinned shipped-3.20b statement: l=0, getter, NUL clamp, lprintf, brace.
needle = 'cryptGetAttributeString(ssh_session, CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL, terminal, &l)'
hits = [i for i, s in enumerate(src) if needle in s]
assert len(hits) == 1, hits
i = hits[0]
assert src[i - 1].strip() == 'l = 0;'
assert src[i + 1].strip() == 'if (l < (int)sizeof(terminal))'
assert src[i + 4].strip() == 'terminal[sizeof(terminal)-1] = 0;'
assert src[i + 5].strip().startswith('lprintf(LOG_DEBUG')
assert src[i + 6].strip() == '}'
body = '\n'.join(src[i - 1:i + 7]) + '\n'
Path('vuln320b.inc').write_text(body)
print('vuln320b.inc: answer.cpp lines %d-%d, %d bytes' % (i, i + 7, len(body)))
PY
