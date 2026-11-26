# Compare the first and second case-map buffer allocations in one request.
# Harness-only gdb observation; never part of a rung-5 claim.
set pagination off
set confirm off
set print thread-events off
python
import gdb, os
root = '/home/mesh-home/mishe-tauftauf2shell'
n = int(os.environ['RUBY2SHELL_WATCH_N'])
port = int(os.environ['RUBY2SHELL_WATCH_PORT'])
gdb.execute('set environment GEM_PATH ' + root + '/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0')
gdb.execute('set environment RUBY2SHELL_STOCK_PORT %d' % port)
gdb.execute('set environment RUBY2SHELL_STOCK_SETTLE 0')
state = {'start': 0, 'end': 0, 'hits': 0}
EXPECTED = b'a' + b'\xdf' * (n - 1)

class CaseMapAlloc(gdb.Breakpoint):
    def __init__(self):
        super().__init__('string.c:7839')
    def stop(self):
        src = int(gdb.parse_and_eval('(char *)source_current'))
        end = int(gdb.parse_and_eval('(char *)source_end'))
        raw = gdb.selected_inferior().read_memory(src, end - src).tobytes()
        if not (raw == b'\xdf' * len(raw) or raw == b'a' + b'\xdf' * (len(raw) - 1)):
            return False
        state['hits'] += 1
        buf = int(gdb.parse_and_eval('(char *)current_buffer'))
        capa = int(gdb.parse_and_eval('current_buffer->capa'))
        if state['hits'] == 1:
            state['start'] = buf + 24 + capa
            state['end'] = state['start'] + (2 * n - capa)
            print('=== FIRST N=%d capa=%d buf=%#x overflow=[%#x,%#x) ===' %
                  (n, capa, buf, state['start'], state['end']))
        else:
            overlap = state['start'] - 32 <= buf <= state['end'] + 32
            print('=== SECOND #%d capa=%d buf=%#x delta_first=%#x overlap=%d ===' %
                  (state['hits'], capa, buf, buf - state['start'], overlap))
        return False

class Abort(gdb.Breakpoint):
    def __init__(self):
        super().__init__('abort')
    def stop(self):
        print('=== ABORT case_map_hits=%d ===' % state['hits'])
        return False
CaseMapAlloc()
Abort()
end
run
quit
