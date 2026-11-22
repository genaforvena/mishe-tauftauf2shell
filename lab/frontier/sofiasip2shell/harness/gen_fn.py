#!/usr/bin/env python3
"""Extract ws_read_frame verbatim from a pinned ws.c by brace matching."""
import sys

src_path, out_path = sys.argv[1], sys.argv[2]
text = open(src_path, encoding="utf-8").read()
marker = "ssize_t ws_read_frame(wsh_t *wsh, ws_opcode_t *oc, uint8_t **data)"
start = text.index(marker)
brace = text.index("{", start)
depth = 0
end = None
for i in range(brace, len(text)):
    if text[i] == "{":
        depth += 1
    elif text[i] == "}":
        depth -= 1
        if depth == 0:
            end = i + 1
            break
assert end is not None and text[end - 1] == "}"
slice_ = text[start:end]
open(out_path, "w", encoding="utf-8").write(slice_ + "\n")
print("extracted %d bytes from %s" % (len(slice_), src_path))
