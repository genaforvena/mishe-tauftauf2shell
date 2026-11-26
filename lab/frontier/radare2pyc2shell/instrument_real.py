#!/usr/bin/env python3
"""Apply the W244 real-consumer probes to a pristine radare2 6.1.8 tree.

Usage: python3 instrument_real.py PATH_TO_radare2-6.1.8

Anchors are exact strings from the tagged source; the script refuses to run on
an already-instrumented tree. The large-write short circuit keeps replay fast
and safe: the probe's purpose is to observe the sink arguments and branch,
not to repeat a multi-gigabyte memset.

Observed on 2026-11-26 (rabin2 -s and radare2 -q -c 'is'):
  get_ascii_object n=4294967295 error=0
  get_bytes size=4294967295 alloc_arg=0 usable=1
  r_buf_read len=4294967295 r=-1 fill=4294967296
The r >= 0 guard therefore skips buf.c:496 in the real consumer: the
r_io_fd_read() method takes `int len`, so 0xffffffff truncates to -1.
"""

import hashlib
import sys
from pathlib import Path

EXPECTED = {
    "libr/bin/format/pyc/marshal.c":
        "41698e7886715b57427b166c90101aa132eadec821de66fccbf477a147cbb51c",
    "libr/util/buf.c":
        "538a6784eeb0e7f673625f73fce58e97c957f2b3dd41b90528d2f4b57493a52f",
}


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    if text.count(old) != 1:
        raise SystemExit(f"anchor missing or ambiguous in {path}")
    path.write_text(text.replace(old, new, 1))


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: instrument_real.py PATH_TO_radare2-6.1.8")
    root = Path(sys.argv[1]).resolve()
    for rel, digest in EXPECTED.items():
        path = root / rel
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != digest:
            raise SystemExit(f"{rel}: expected pristine sha256 {digest}, got {actual}")

    marshal = root / "libr/bin/format/pyc/marshal.c"
    replace_once(
        marshal,
        "\tut8 *ret = R_NEWS0 (ut8, size + 1);\n",
        '\tut8 *ret = R_NEWS0 (ut8, size + 1);\n'
        '\tfprintf (stderr, "PROBE get_bytes size=%u alloc_arg=%llu usable=%zu\\n", '
        'size, (unsigned long long)(ut64)(size + 1), ret? malloc_usable_size (ret): 0);\n'
        '\tif (size > 1000000) { return NULL; }\n',
    )
    replace_once(
        marshal,
        "static pyc_object *get_ascii_object(RBuffer *buffer) {\n\tbool error = false;\n"
        "\tut32 n = get_ut32 (buffer, &error);\n\tif (error) {\n\t\treturn NULL;\n\t}\n"
        "\treturn get_ascii_object_generic (buffer, n, true);",
        'static pyc_object *get_ascii_object(RBuffer *buffer) {\n\tbool error = false;\n'
        '\tut32 n = get_ut32 (buffer, &error);\n'
        '\tfprintf (stderr, "PROBE get_ascii_object n=%u error=%d\\n", n, error);\n'
        '\tif (error) {\n\t\treturn NULL;\n\t}\n'
        '\treturn get_ascii_object_generic (buffer, n, true);',
    )
    replace_once(
        marshal,
        '#include "pyc_magic.h"\n',
        '#include "pyc_magic.h"\n#include <malloc.h>\n',
    )

    buf = root / "libr/util/buf.c"
    replace_once(
        buf,
        "\tst64 r = buf_read (b, buf, len);\n",
        '\tst64 r = buf_read (b, buf, len);\n'
        '\tfprintf (stderr, "PROBE r_buf_read len=%llu r=%lld fill=%llu\\n", '
        '(unsigned long long)len, (long long)r, (unsigned long long)(len - r));\n'
        '\tif (len > 1000000) { return r; }\n',
    )
    print(f"instrumented {root}")


if __name__ == "__main__":
    main()
