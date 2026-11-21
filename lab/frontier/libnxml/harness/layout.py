"""gdb helper: print stack locals within +/-64 bytes of a 1024-byte name buffer.

Usage: gdb -q -batch -x layout.py -ex 'break nxml_parser.c:942 if i == 1022' \
       -ex 'run 1022 0' -ex 'showlayout str'
"""
import gdb


class ShowLayout(gdb.Command):
    def __init__(self):
        super().__init__("showlayout", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        buf = arg.strip()
        end = int(gdb.parse_and_eval("&%s[1024]" % buf))
        frame = gdb.selected_frame()
        block = frame.block()
        rows = []
        seen = set()
        while block:
            for var in block:
                if not var.is_variable or not var.name or var.name in seen:
                    continue
                seen.add(var.name)
                try:
                    addr = var.value(frame).address
                except (gdb.error, AttributeError):
                    continue
                if addr is None:
                    continue
                a = int(addr)
                if end - 64 <= a <= end + 96:
                    rows.append((a, var.name))
            block = block.superblock
        print("BUFEND %s %s" % (buf, hex(end)))
        for a, name in sorted(rows):
            print("NEAR %-16s %s delta=%d" % (name, hex(a), a - end))


ShowLayout()
