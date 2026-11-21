import sys, gc
class F:
    def __del__(self):
        print("DEL refcnt_arg=%d" % sys.getrefcount(self), file=sys.stderr)
# refcount path
a = F(); del a
# GC path via cycle
b = F(); b.me = b; del b
gc.collect()
print("DONE")
