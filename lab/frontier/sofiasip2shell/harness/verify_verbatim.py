#!/usr/bin/env python3
"""Assert the generated fns-*.inc is an exact substring of the pinned source."""
import sys

inc_path, src_path = sys.argv[1], sys.argv[2]
inc = open(inc_path, encoding="utf-8").read().rstrip("\n")
src = open(src_path, encoding="utf-8").read()
assert inc in src, "%s is not a verbatim substring of %s" % (inc_path, src_path)
print("VERBATIM OK %s (%d bytes) in %s" % (inc_path, len(inc), src_path))
