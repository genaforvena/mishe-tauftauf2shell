import gdb
ARENA = 0x7ffff7a04ac0

def rd(addr):
    return int(gdb.parse_and_eval('*(unsigned long*)%d' % addr))

def sysmem():
    try:
        return int(gdb.parse_and_eval('((struct malloc_state*)%d)->system_mem' % ARENA))
    except Exception:
        return 0

def dump_chunk(tag, a):
    print('%s chunk=0x%x prev_size=0x%x sizefield=0x%x (size=0x%x flags=%d)' %
          (tag, a, rd(a), rd(a + 8), rd(a + 8) & ~7, rd(a + 8) & 7))

def walk_unsorted():
    rcx = int(gdb.parse_and_eval('$rcx'))
    r8  = int(gdb.parse_and_eval('$r8'))
    o   = rcx - 0x10
    osz = rd(o + 8) & ~7
    print('ORIGIN ptr=0x%x len=%d chunk=0x%x sizefield=0x%x' %
          (rcx, r8, o, rd(o + 8)))
    v = o + osz
    vsz = rd(v + 8) & ~7
    print('VICTIM chunk=0x%x prev_size=0x%x sizefield=0x%x (size=0x%x)' %
          (v, rd(v), rd(v + 8), vsz))
    fd = rd(v + 0x10); bk = rd(v + 0x18)
    print('V fd=0x%x bk=0x%x' % (fd, bk))
    sentinel = None
    if fd == bk:
        sentinel = fd
        print('unsorted head sentinel=0x%x' % sentinel)
        try:
            print('system_mem=0x%x' % sysmem())
        except Exception:
            pass
    # the decisive operand: chunk at V + chunksize(V)
    nxt = v + vsz
    print('--- chunk at V+size (0x%x): the "next size" operand ---' % nxt)
    for i in range(4):
        print('  0x%x: 0x%016x 0x%016x' % (nxt + i*0x10 - 0x10, rd(nxt + i*0x10 - 0x10), rd(nxt + i*0x10 - 0x8)))
    print('  -> chunksize_nomask(next)=0x%x  prev_size(next)=0x%x  prev_inuse(next)=%d' %
          (rd(nxt + 8) & ~7, rd(nxt), rd(nxt + 8) & 1))
    # walk the whole ring via the sentinel
    if sentinel:
        print('--- unsorted ring from sentinel ---')
        p = rd(sentinel + 0x18)  # sentinel->bk = first victim
        for i in range(20):
            if p == sentinel:
                print('ring closed at sentinel'); break
            sz = rd(p + 8) & ~7
            n2 = p + sz
            print('ring%d: chunk=0x%x sizefield=0x%x fd=0x%x bk=0x%x' %
                  (i, p, rd(p + 8), rd(p + 0x10), rd(p + 0x18)))
            print('   next=0x%x next_sizefield=0x%x next_prev_size=0x%x next_prev_inuse=%d' %
                  (n2, rd(n2 + 8), rd(n2), rd(n2 + 8) & 1))
            p = rd(p + 0x18)
    try:
        top = int(gdb.parse_and_eval('((struct malloc_state*)%d)->top' % ARENA))
        print('ARENA TOP=0x%x' % top)
    except Exception as e:
        print('top fail %s' % e)
    print('--- raw V..V+0x40 ---')
    a = v
    for i in range(4):
        print('  0x%x: 0x%016x 0x%016x' % (a, rd(a), rd(a + 8)))
        a += 0x10
