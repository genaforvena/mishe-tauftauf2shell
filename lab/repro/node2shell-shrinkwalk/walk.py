import os
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
        HITS['len1'] = r8
        fp1 = o + 0xF + r8
        print('FAKE-PAIR@HIT1 0x%x qword=0x%x +8=0x%x +0x10=0x%x'
              % (fp1, rd_try(fp1), rd_try(fp1 + 8), rd_try(fp1 + 0x10)))
        walk_unsorted()
        return
    o1 = HITS.get('o1', 0)
    # wake 11: the R1-origin "own-NUL" fake pair at o1+0xF+len1
    l1 = HITS.get('len1', 0)
    if o1 and l1:
        fp = o1 + 0xF + l1
        fq = rd_try(fp)
        v0 = o + (rd(o + 8) & ~7)
        print('FAKE-PAIR 0x%x qword=0x%x (o1=0x%x len1=%d) V-minus-FAKE=0x%x'
              % (fp, fq if fq is not None else -1, o1, l1, v0 - fp))
    print('O2-vs-O1: O2=0x%x O1=0x%x same=%s' % (o, o1, o == o1))
    if o == o1:
        # O2 was carved at exactly O1's old address: the "HOLE1"
        # inventory would read O2's own live header and string content
        # (fd/bk look like stale bytes) — skip it.
        # wake 12: the O2==O1 geometry is the one where V is carved from
        # the consolidated O1+copy donor and may be >= request (hence
        # splittable). Dump V and the fake-field window; FAKE_PATCH env
        # works here too via the shared path below (diagnostic only).
        v2o = o + (rd(o + 8) & ~7)
        v2o_sf = rd_try(v2o + 8)
        print('O2==O1-VICTIM chunk=0x%x sizefield=0x%x'
              % (v2o, v2o_sf if v2o_sf is not None else -1))
        if v2o_sf is not None:
            bso = v2o_sf & ~7
            bno = v2o + bso
            print('O2==O1-BELIEVED-NEXT 0x%x sizefield=0x%x prev_size=0x%x'
                  % (bno, rd_try(bno + 8) or 0, rd_try(bno) or 0))
            for a in range(bno - 0x20, bno + 0x30, 8):
                q = rd_try(a)
                print('  0x%x: 0x%016x' % (a, q if q is not None else -1))
            # wake 12: locate the request-1 ALT marker and the origin 'z'
            # tail inside V. Their addresses pin the consolidated donor's
            # copy-twin boundary, so L1/L2/ALT can be tuned to put the
            # fake window on a real chunk header (prev_size == size).
            altpat = 0x3030303830783268  # "h2x:80000" little-endian
            found = []
            for a in range(v2o, min(v2o + 0x1200, v2o + bso + 0x200), 8):
                q = rd_try(a)
                if q is None:
                    break
                if q == altpat or (q & 0xffff) == 0x007a:
                    found.append((a, q))
            print('O2==O1-MARKERS (ALT-start / z+NUL) within V: %s'
                  % ' '.join('0x%x=0x%x' % (a, q) for a, q in found[:12]))
            acand = ((l1 + 8 + 15) & ~15) if l1 else 0
            if acand:
                for label, off in (('O1+A', acand), ('O1+A+0x10', acand + 0x10),
                                   ('O1+A+0x20', acand + 0x20)):
                    print('%s 0x%x sizefield=0x%x prev_size=0x%x'
                          % (label, o + off, rd_try(o + off + 8) or 0,
                             rd_try(o + off) or 0))
            # wake 12: same debugger-only fake-field patch as the shared
            # path, so the O2==O1 / V>=request geometry can be tested
            # through the full gate chain (NOT attacker bytes).
            fpatch = os.environ.get('FAKE_PATCH')
            if fpatch and bno is not None:
                gdb.parse_and_eval('*(unsigned long*)%d = %d'
                                   % (bno + 8, int(fpatch, 0)))
                gdb.parse_and_eval('*(unsigned long*)%d = %d' % (bno, bso))
                print('O2==O1-FAKE-PATCH wrote sizefield=0x%x prev_size=0x%x at 0x%x (debugger)'
                      % (int(fpatch, 0), bso, bno))
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
    fv = os.environ.get('FAKE_VSIZE')
    if fv and v2sf is not None:
        gdb.parse_and_eval('*(unsigned long*)%d = %d'
                           % (v2 + 8, int(fv, 0)))
        v2sf = rd_try(v2 + 8)
        print('FAKE-VSIZE (debugger) set V sizefield to 0x%x' % v2sf)
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
        # wake 7: believed size is post-NUL (byte0 zeroed) — the REAL
        # size is believed | destroyed byte0. Dump the believed-next
        # header bytes (the fake-header groom target for a free victim)
        # and scan the tail for the real next chunk: a 16-aligned spot
        # holding a sane sizefield with prev_inuse=1 (it follows the
        # in-use-or-just-NULed victim). prev_size of that candidate
        # equals the victim's REAL size when the victim was ever freed.
        bs = v2sf & ~7
        bn = v2 + bs
        bnh = rd_try(bn + 8)
        print('VICTIM-BELIEVED-NEXT 0x%x sizefield=0x%x prev_size=0x%x' %
              (bn, bnh if bnh is not None else -1, rd_try(bn) or 0))
        # Wake 11 DIAGNOSTIC ONLY: FAKE_PATCH writes a chosen qword into
        # the believed-next sizefield via gdb. This is a debugger
        # intervention, NOT attacker-controlled bytes — used solely to
        # test whether a sane fake-next is the last gate to a split.
        patch = os.environ.get('FAKE_PATCH')
        if patch:
            gdb.parse_and_eval('*(unsigned long*)%d = %d'
                               % (bn + 8, int(patch, 0)))
            print('FAKE-PATCH (debugger) wrote 0x%x at 0x%x'
                  % (int(patch, 0), bn + 8))
            # glibc's unsorted scan also checks prev_size(next)==believed.
            gdb.parse_and_eval('*(unsigned long*)%d = %d' % (bn, bs))
            print('FAKE-PATCH (debugger) wrote prev_size=0x%x at 0x%x'
                  % (bs, bn))
        print('--- raw window around believed-next (value-end/zero-tail check) ---')
        for a in range(v2 + bs - 0x30, v2 + bs + 0x10, 8):
            q = rd_try(a)
            print('  0x%x: 0x%016x' % (a, q if q is not None else -1))
        for a in range(v2 + bs + 0x10, v2 + bs + 0x80, 8):
            q = rd_try(a)
            print('  0x%x: 0x%016x' % (a, q if q is not None else -1))
        # wake 9: content profile of the victim span — where do the
        # stale bytes (attacker strings / serialized frames) end and
        # the zeros begin. The outbuf lane needs a fake sizefield
        # [odd byte][7 zero bytes] somewhere inside [v2+0x10,
        # v2+bs+0x80): print each zero<->nonzero qword transition.
        print('--- victim content profile (zero/nonzero qword runs) ---')
        prev_nz = None
        shown = 0
        for a in range(v2 + 0x10, v2 + bs + 0x80, 8):
            q = rd_try(a)
            nz = q is not None and q != 0
            if prev_nz is None or nz != prev_nz:
                print('  0x%x: %s' % (a, 'NZ 0x%016x' % q if nz else 'zero'))
                prev_nz = nz
                shown += 1
                if shown >= 24:
                    print('  ... (transitions capped at 24)')
                    break
        for k in range(bs + 0x10, bs + 0x200, 0x10):
            sf2 = rd_try(v2 + k + 8)
            if sf2 is not None and 0x20 <= (sf2 & ~7) <= 0x2000 and (sf2 & 1) == 1:
                print('REAL-NEXT-CAND chunk=0x%x sizefield=0x%x prev_size=0x%x -> real size 0x%x'
                      % (v2 + k, sf2, rd_try(v2 + k) or 0, k))
                break
    walk_unsorted()
