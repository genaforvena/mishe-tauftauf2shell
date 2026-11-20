import gdb
ARENA = 0x7ffff7a04ac0

def rd(addr):
    return int(gdb.parse_and_eval('*(unsigned long*)%d' % addr))

def rd_try(addr):
    try:
        return int(gdb.parse_and_eval('*(unsigned long*)%d' % addr))
    except gdb.MemoryError:
        return None

def arena_top():
    try:
        return int(gdb.parse_and_eval('((struct malloc_state*)%d)->top' % ARENA))
    except Exception:
        return 0

def sysmem():
    try:
        return int(gdb.parse_and_eval('((struct malloc_state*)%d)->system_mem' % ARENA))
    except Exception:
        return 0

def dump_chunk(tag, a):
    print('%s chunk=0x%x prev_size=0x%x sizefield=0x%x (size=0x%x flags=%d)' %
          (tag, a, rd(a), rd(a + 8), rd(a + 8) & ~7, rd(a + 8) & 7))

def nul_class(length):
    # The NUL is written at o+0x10+len (user start + len). With
    # chunk(o) = align(len+8, 16), the landing offset inside the NEXT
    # chunk is 0x10+len-chunk: == 8 exactly when len % 16 == 8 (the
    # sizefield LSB — the only corrupting class); 0..7 when
    # len % 16 == 0..7 (the next chunk's prev_size bytes, harmless:
    # unused while the predecessor is in use and rewritten by
    # free()'s set_foot otherwise); negative when len % 16 == 9..15
    # (the NUL never leaves the origin allocation — harmless).
    chunk = (length + 8 + 15) & ~15
    off = 0x10 + length - chunk
    if off == 8:
        return 'NEXT-SIZEFIELD LSB — CORRUPTING (len %% 16 == 8)' % ()
    if 0 <= off <= 7:
        return 'next prev_size byte %d — harmless' % off
    return 'own-chunk slack (off=%d) — harmless' % off

def walk_unsorted():
    rcx = int(gdb.parse_and_eval('$rcx'))
    r8  = int(gdb.parse_and_eval('$r8'))
    o   = rcx - 0x10
    osz = rd(o + 8) & ~7
    print('ORIGIN ptr=0x%x len=%d chunk=0x%x sizefield=0x%x' %
          (rcx, r8, o, rd(o + 8)))
    print('NUL-CLASS: %s' % nul_class(r8))
    v = o + osz
    vsz = rd(v + 8) & ~7
    print('VICTIM chunk=0x%x prev_size=0x%x sizefield=0x%x (size=0x%x)' %
          (v, rd(v), rd(v + 8), vsz))
    # top-victim regime: the NUL landed on the top chunk's sizefield.
    # glibc keeps top_end == brk, so real size = sbrk(0) - top; the
    # believed extent ends INSIDE the real top. Skip the unsorted walk
    # (reads past believed end run off brk) and measure the shrink.
    top = arena_top()
    if top and v == top:
        try:
            brk = int(gdb.parse_and_eval('(long)sbrk(0)'))
            real = brk - top
            print('TOP-VICTIM: top=0x%x believed_size=0x%x real_size=0x%x '
                  'shrink=0x%x brk=0x%x' % (top, vsz, real, real - vsz, brk))
            if real > vsz:
                print('TOP-VICTIM: PERSISTENT SHRINK of live top sizefield — '
                      'no validator inside the request, run may complete')
            elif real == vsz:
                if nul_class(r8).startswith('NEXT-SIZEFIELD'):
                    print('TOP-VICTIM: flag-only write (no size shrink)')
                else:
                    print('TOP-VICTIM: no size change and the NUL did not '
                          'hit the sizefield (class: %s) — no corruption' %
                          nul_class(r8))

            return
        except Exception as e:
            print('top-victim probe fail %s' % e)
            return
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

# wake 6 — two-request hole inventory (run-multi.sh / multi-client.js).
# Hit 1 records O1 (request 1's origin chunk) and walks as usual.
# Hit 2 first inventories the freed O1 hole: its current sizefield,
# fd/bk, and — decisively — the PREV_INUSE bit of the chunk abutting
# the hole (hole free iff that bit is 0), plus the inuse state of that
# abutting chunk itself via the chunk after it. Then walks O2.
HITS = {'n': 0}

def multi_walk():
    rcx = int(gdb.parse_and_eval('$rcx'))
    r8  = int(gdb.parse_and_eval('$r8'))
    o   = rcx - 0x10
    HITS['n'] += 1
    hit = HITS['n']
    print('=== HIT %d ORIGIN ptr=0x%x len=%d chunk=0x%x sizefield=0x%x' %
          (hit, rcx, r8, o, rd(o + 8)))
    print('NUL-CLASS: %s' % nul_class(r8))
    if hit == 1:
        HITS['o1'] = o
        walk_unsorted()
        return
    o1 = HITS.get('o1', 0)
    print('O2-vs-O1: O2=0x%x O1=0x%x same=%s' % (o, o1, o == o1))
    if o == o1:
        # O2 was carved at exactly O1's old address: the "HOLE1"
        # inventory would read O2's own live header and string content
        # (fd/bk look like stale bytes) — skip it.
        print('O2 occupies the O1 hole — HOLE1 inventory skipped')
        walk_unsorted()
        return
    sf = rd_try(o1 + 8)
    if sf is None:
        print('HOLE1 chunk=0x%x UNREADABLE' % o1)
    else:
        sz1 = sf & ~7
        fd = rd_try(o1 + 0x10); bk = rd_try(o1 + 0x18)
        nxt = o1 + sz1
        nsf = rd_try(nxt + 8)
        freetag = 'UNKNOWN' if nsf is None else ('FREE' if (nsf & 1) == 0 else 'IN-USE')
        print('HOLE1 chunk=0x%x sizefield=0x%x (size=0x%x) fd=0x%x bk=0x%x -> %s' %
              (o1, sf, sz1, fd, bk, freetag))
        if nsf is not None:
            nsz = nsf & ~7
            print('HOLE1-NEXT chunk=0x%x sizefield=0x%x (size=0x%x) prev_inuse=%d' %
                  (nxt, nsf, nsz, nsf & 1))
            nn = nxt + nsz
            nnf = rd_try(nn + 8)
            if nnf is not None:
                print('HOLE1-NEXT inuse=%d (via sizefield of chunk after it)' % (nnf & 1))
            if o == nxt:
                print('O2 == HOLE1-NEXT: request-2 origin carved exactly abutting the freed O1 hole')
    # O2's victim classification: a free unsorted victim (fd==bk==arena
    # sentinel) means the in-call malloc validator aborts; IN-USE is
    # claimed only when the believed-next address actually holds a sane
    # chunk header (content bytes there have fooled this before).
    vsz2 = rd(o + 8) & ~7
    v2 = o + vsz2
    v2sf = rd_try(v2 + 8)
    if v2sf is not None:
        fd2 = rd_try(v2 + 0x10); bk2 = rd_try(v2 + 0x18)
        nn = v2 + (v2sf & ~7)
        nnf = rd_try(nn + 8)
        sm = sysmem()
        in_unsorted = (fd2 is not None and fd2 == bk2
                       and ARENA <= fd2 < ARENA + 0x2000)
        sane_next = (nnf is not None and 0x20 <= (nnf & ~7) <= sm)
        if in_unsorted:
            tag = 'FREE(unsorted) — validator abort expected'
        elif sane_next:
            tag = 'IN-USE (believed-next header sane: 0x%x)' % nnf
        else:
            tag = 'UNKNOWN (believed-next 0x%x is content, fd/bk=0x%x/0x%x)' % (nnf, fd2, bk2)
        print('O2-VICTIM chunk=0x%x sizefield=0x%x -> %s' % (v2, v2sf, tag))
    walk_unsorted()
