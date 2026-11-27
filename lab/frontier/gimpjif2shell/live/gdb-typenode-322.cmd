# W322: no-shim inspection of the TypeNode that owns the GData at
# indexes+272. Stop at the wrapped inflate(), derive TypeNode = GData - 0x28
# from the validated GLib 2.84 layout, and use only pure GLib lookups
# (g_quark_to_string, g_type_name) to name it. No plugin or heap byte is
# changed and no pointer is followed except the two pure lookup calls.
set pagination off
set confirm off
set print thread-events off
set breakpoint pending on
python
class TypeNodeProbe(gdb.Breakpoint):
    def stop(self):
        try:
            strm = int(gdb.parse_and_eval("$rdi"))
            avail = int(gdb.parse_and_eval("*(unsigned int*)(%d+32)" % strm))
            if avail != 2147483778:
                return False
            idx = int(gdb.parse_and_eval("*(void**)(%d+24)" % strm))
        except Exception as e:
            print("W322 READ FAILED: %s" % e)
            return False

        def word(addr):
            try:
                return int(gdb.parse_and_eval("*(unsigned long*)%d" % addr))
            except Exception:
                return None

        gdata = idx + 272
        node = gdata - 0x28
        print("=== W322 PRE-INFLATE indexes=%#x gdata=%#x node=%#x ===" %
              (idx, gdata, node))
        gdb.execute("x/24gx %d" % node)
        back = word(node + 0x28)
        qname = word(node + 0x20)
        gtype = word(node + 0x48)
        print("=== W322 BACKPOINTER node+40=%s expected=%#x ===" %
              ("%#x" % back if back is not None else "UNREADABLE", gdata))
        print("=== W322 RAW qname=%s gtype=%s ===" %
              ("%#x" % qname if qname is not None else "UNREADABLE",
               "%#x" % gtype if gtype is not None else "UNREADABLE"))
        if back is None or back != gdata:
            print("=== W322 BACKPOINTER MISMATCH: no TypeNode claim ===")
            return False
        for label, expr in (
            ("GQuark name", "(char*) g_quark_to_string(%d)" % (qname or 0)),
            ("GType name", "(char*) g_type_name((unsigned long)%d)" % (gtype or 0)),
        ):
            try:
                value = gdb.parse_and_eval(expr)
                print("=== W322 %s = %s ===" % (label, value))
            except Exception as e:
                print("=== W322 %s CALL FAILED: %s ===" % (label, e))
        return False

TypeNodeProbe("inflate")
end
run
