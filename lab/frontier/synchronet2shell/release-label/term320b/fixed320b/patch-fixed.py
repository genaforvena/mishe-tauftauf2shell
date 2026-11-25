#!/usr/bin/env python3
"""Replace the 3.20b no-size TERM copy with the pinned cb6d77dbca statements.

The copy logic is read verbatim from harness/fixed.inc (pinned
answer-fixed.cpp lines 542-549, extracted by harness/gen.sh).  The only
mechanical adaptation to the older shipped 3.20b source is that
client_socket is a plain int there, not the atomic used in the 3.22 parent:
client_socket.load() -> client_socket.  One instrumentation lprintf is
inserted after the pinned lprintf; it changes no copy logic.
"""
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[3]
src = root / "src-tree/320b/src/sbbs3/answer.cpp"
pinned = (root / "harness/fixed.inc").read_text().splitlines()

probe = (
    '\t\t\tlprintf(LOG_DEBUG, "%04d SSH FIXED_320B_PROBE sizeof=%u wire=%u '
    'len=%u off41=%02x cv=%08x first=%p last=%p", client_socket, '
    '(unsigned)sizeof(terminal), (unsigned)ssh_terminal_length, '
    '(unsigned)strlen(terminal), (unsigned)((unsigned char*)terminal)[41], '
    '(unsigned)cterm_version, (void*)savedlines.first, '
    '(void*)savedlines.last);'
)

adapted = [ln.replace("client_socket.load()", "client_socket") for ln in pinned]
if not any(a != b for a, b in zip(adapted, pinned)):
    sys.exit("PINNED_ADAPTATION_MISSING")
body = adapted[:6] + [probe] + adapted[6:]

text = src.read_text()
start_marker = (
    "\t\tl = 0;\n"
    "\t\tif (cryptStatusOK(cryptGetAttributeString(ssh_session, "
    "CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL, terminal, &l)) && l > 0) {"
)
end_marker = "\t\tpthread_mutex_unlock(&ssh_mutex);"
if text.count(start_marker) != 1:
    sys.exit("VULN_BLOCK_NOT_UNIQUE")
start = text.index(start_marker)
end = text.index(end_marker, start)
src.write_text(text[:start] + "\n".join(body) + "\n" + text[end:])

# Verify what was written: strip the one probe line, restore the atomic spelling,
# and require an exact byte-for-byte match with the pinned fixed hunk.
written = src.read_text().splitlines()
i = written.index(adapted[0])
restored = [ln for ln in written[i:i + len(body)] if "FIXED_320B_PROBE" not in ln]
restored = [ln.replace("client_socket", "client_socket.load()") if ln in adapted else ln
            for ln in restored]
if restored != pinned:
    sys.exit("FIXED_HUNK_MISMATCH: %r != %r" % (restored, pinned))
print("FIXED_HUNK_PINNED_OK lines=%d probe=1" % len(pinned))
