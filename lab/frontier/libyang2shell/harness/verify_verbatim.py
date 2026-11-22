#!/usr/bin/env python3
"""Check that every function in the harness includes is a verbatim pin slice."""
import pathlib
import gen_fn

HERE = pathlib.Path(__file__).resolve().parent
SRC = HERE.parent / "src"
INFILE = (SRC / "in.c.pin").read_text()
NAMES = ("lyb_read", "lyb_read_size", "lyb_read_string")

for label, pin in gen_fn.PINS.items():
    inc = (HERE / f"fns-{label}.inc").read_text()
    parser = (SRC / f"parser_lyb-{pin}.c").read_text()
    for name in NAMES:
        expected = gen_fn.extract(parser, name)
        assert expected in inc, (label, name, "not a verbatim pin slice")
    expected_in = gen_fn.extract(INFILE, "ly_in_read")
    assert expected_in in inc, (label, "ly_in_read", "not a verbatim pin slice")
print("VERBATIM_OK 3 pins x 3 parser functions + pinned ly_in_read")
