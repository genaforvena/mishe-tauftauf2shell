#!/usr/bin/env python3
"""Extract the pinned RTF_PREBUF define and two functions verbatim.

Usage: gen_fn.py ../src/ytnef-<pin>.c fns-<pin>.inc
No reconstruction: every emitted source line is an exact substring of the pin.
"""
import pathlib
import re
import sys


def brace_slice(text, start):
    brace = text.index("{", start)
    depth = 0
    for i in range(brace, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    raise ValueError("unbalanced braces")


def function(text, pattern):
    m = re.search(pattern, text, re.M)
    if not m:
        raise ValueError("function not found: " + pattern)
    return brace_slice(text, m.start())


def main():
    src = pathlib.Path(sys.argv[1]).read_text()
    out = pathlib.Path(sys.argv[2])
    prebuf = re.search(r"^#define RTF_PREBUF .*$", src, re.M)
    if not prebuf:
        raise ValueError("RTF_PREBUF not found")
    swap = function(src, r"^DWORD SwapDWord\(")
    decomp = function(src, r"^BYTE \*DecompressRTF\(")
    out.write_text(
        "/* Verbatim pinned slices from %s; regenerated every run. */\n"
        "%s\n%s\n%s\n" % (sys.argv[1], prebuf.group(0), swap, decomp)
    )
    print("EXTRACTED %s RTF_PREBUF=%d SwapDWord=%d DecompressRTF=%d" %
          (sys.argv[2], len(prebuf.group(0)), len(swap), len(decomp)))


if __name__ == "__main__":
    main()
