# Rung-4 probe: identify which ngtcp2_pktns sits at pers_inbuf+6144.
# At the F6 wire_buf_consume breakpoint, walk the stack for a live
# ngtcp2_conn*, then compare conn->in_pktns / hs_pktns / &conn->pktns with
# slot1, and scan nearby heap for live pointers to slot1.
set pagination off
set confirm off
cd /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
python
import gdb

DIRECT = '/home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/harness/pktns-owner-direct.txt'


def dlog(msg):
    gdb.write(msg)
    with open(DIRECT, 'a') as fh:
        fh.write(msg)
        fh.flush()


open(DIRECT, 'w').close()


class F6Owner(gdb.Breakpoint):
    def stop(self):
        try:
            wb = int(gdb.parse_and_eval('$rdi'))
            length = int(gdb.parse_and_eval('$rsi'))
            dlog('wire_buf_consume len=%d\n' % length)
            if length != 1198:
                return False
            buf = int(gdb.parse_and_eval('*(unsigned long*)%d' % wb))
            slot1 = buf + 6144
            dlog('F6 buf=0x%x slot1=0x%x len=%d\n' % (buf, slot1, length))

            conn = 0
            frame = gdb.newest_frame()
            depth = 0
            while frame is not None and depth < 40:
                try:
                    block = frame.block()
                    for sym in block:
                        if sym.name not in ('conn', 'ngconn'):
                            continue
                        try:
                            val = int(frame.read_var(sym))
                        except Exception:
                            continue
                        if 0x100000000000 < val < 0x800000000000:
                            conn = val
                            dlog('found %s=0x%x in frame %d %s\n'
                                 % (sym.name, conn, depth, frame.name()))
                            break
                except Exception:
                    pass
                if conn:
                    break
                frame = frame.older()
                depth += 1

            if not conn:
                dlog('NO CONN FOUND in %d frames\n' % depth)
                return False

            def evalp(expr):
                try:
                    return int(gdb.parse_and_eval(expr))
                except Exception as exc:
                    dlog('eval failed: %s (%s)\n' % (expr, exc))
                    return 0

            cast = '((ngtcp2_conn *)%d)' % conn
            inp = evalp(cast + '->in_pktns')
            hsp = evalp(cast + '->hs_pktns')
            app = evalp('&' + cast + '->pktns')
            dlog('conn=0x%x in_pktns=0x%x hs_pktns=0x%x embedded_pktns=0x%x\n'
                 % (conn, inp, hsp, app))
            dlog('match: in=%d hs=%d embedded=%d\n'
                 % (int(inp == slot1), int(hsp == slot1), int(app == slot1)))
            for name, addr in (('slot1', slot1), ('in_pktns', inp),
                               ('hs_pktns', hsp), ('embedded', app)):
                if addr:
                    gid = evalp('((ngtcp2_pktns *)%d)->id' % addr)
                    dlog('%s id=%d (0=INITIAL,1=HANDSHAKE,2=APPLICATION)\n'
                         % (name, gid))
            tls = evalp('*(unsigned long*)((char*)%d + 7648)' % conn)
            dlog('tls_native_handle=0x%x at conn+7648 match_slot1=%d\n'
                 % (tls, int(tls == slot1)))

            inferior = gdb.selected_inferior()
            lo, hi = conn - 0x200000, conn + 0x200000
            block = bytes(inferior.read_memory(lo, hi - lo))
            needle = slot1.to_bytes(8, 'little')
            idx, count = block.find(needle), 0
            while idx >= 0 and count < 12:
                dlog('ptr-to-slot1 at 0x%x (conn%+d)\n'
                     % (lo + idx, lo + idx - conn))
                idx = block.find(needle, idx + 1)
                count += 1
            dlog('ptr-to-slot1 matches=%d in [0x%x,0x%x]\n' % (count, lo, hi))
        except Exception:
            import traceback
            dlog(traceback.format_exc())
        return False


F6Owner('wire_buf_consume')
end
run -n -c /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc/config /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
printf "STOP: rip=%p\n", $pc
