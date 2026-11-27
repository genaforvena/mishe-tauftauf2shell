# W322 second probe: find the heap word that points at the GData object, then
# treat its address as TypeNode+0x28 and name the GType with pure GLib lookups.
# The first probe (gdb-typenode-322.cmd) wrongly assumed TypeNode == GData-0x28
# and was refused by its own backpointer check; that assumption is retired.
set pagination off
set confirm off
set print thread-events off
set breakpoint pending on
python
import re

class ScanProbe(gdb.Breakpoint):
    def stop(self):
        try:
            strm = int(gdb.parse_and_eval("$rdi"))
            avail = int(gdb.parse_and_eval("*(unsigned int*)(%d+32)" % strm))
            if avail != 2147483778:
                return False
            idx = int(gdb.parse_and_eval("*(void**)(%d+24)" % strm))
        except Exception as e:
            print("W322 SCAN READ FAILED: %s" % e)
            return False

        def word(addr):
            try:
                return int(gdb.parse_and_eval("*(unsigned long*)%d" % addr))
            except Exception:
                return None

        gdata = idx + 272
        lo = hi = None
        for line in gdb.execute("info proc mappings", to_string=True).splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            try:
                start = int(parts[0], 16)
                end = int(parts[1], 16)
            except ValueError:
                continue
            if start <= idx < end and parts[4] == "rw-p":
                lo, hi = start, end
                break
        print("=== W322 SCAN gdata=%#x heap=%s-%s ===" %
              (gdata, "%#x" % lo if lo else "UNKNOWN",
               "%#x" % hi if hi else "UNKNOWN"))
        if lo is None:
            return False
        found = gdb.execute("find /g %d, %d, %d" % (lo, hi, gdata),
                            to_string=True)
        print("=== W322 FIND RESULT ===\n%s" % found)
        hits = [int(v, 16) for v in re.findall(r'0x[0-9a-fA-F]+', found)]
        for addr in hits[:10]:
            node = addr - 0x28
            qname = word(node + 0x20)
            gtype = word(node + 0x48)
            print("=== W322 HIT %#x node=%#x qname=%s gtype=%s ===" %
                  (addr, node,
                   "%#x" % qname if qname is not None else "UNREADABLE",
                   "%#x" % gtype if gtype is not None else "UNREADABLE"))
            if qname is None or not (0 < qname < 0x100000):
                continue
            for label, expr in (
                ("GQuark name", "(char*) g_quark_to_string(%d)" % qname),
                ("GType name", "(char*) g_type_name((unsigned long)%d)" % (gtype or 0)),
            ):
                try:
                    print("=== W322 HIT %#x %s = %s ===" %
                          (addr, label, gdb.parse_and_eval(expr)))
                except Exception as e:
                    print("=== W322 HIT %#x %s CALL FAILED: %s ===" %
                          (addr, label, e))
        return False

ScanProbe("inflate")
end
run
