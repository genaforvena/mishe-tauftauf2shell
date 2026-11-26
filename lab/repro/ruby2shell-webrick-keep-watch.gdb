# Ruby2Shell same-worker keep-alive reader watch.
# Tracks every read of the overflow byte across three requests on ONE
# WEBrick keep-alive connection. Started under gdb by
# ruby2shell-webrick-keep-watch.sh; the client is external.
set pagination off
set confirm off
set print thread-events off
python
import gdb
import os
root = '/home/mesh-home/mishe-tauftauf2shell'
n = int(os.environ['RUBY2SHELL_WATCH_N'])
port = int(os.environ['RUBY2SHELL_WATCH_PORT'])
gdb.execute('set environment GEM_PATH ' + root + '/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0')
gdb.execute('set environment RUBY2SHELL_STOCK_PORT %d' % port)
gdb.execute('set environment RUBY2SHELL_STOCK_SETTLE 0')
end
break abort
commands
  printf "=== ABORT ===\n"
  bt 24
  quit
end
python
import gdb
EXPECTED = b'a' + b'\xdf' * (int(os.environ['RUBY2SHELL_WATCH_N']) - 1)
state = {'target': 0, 'old': 0, 'buf': 0, 'reads': 0}
class MallocFinish(gdb.FinishBreakpoint):
    def __init__(self, size):
        super().__init__(gdb.newest_frame(), internal=True)
        self.size = size
    def stop(self):
        ret = int(gdb.parse_and_eval('$rax'))
        if state['target'] and abs(ret - state['target']) < 0x2000:
            print('=== NEAR_MALLOC size=%#x ret=%#x delta=%#x ===' %
                  (self.size, ret, ret - state['target']))
        return False
class MallocProbe(gdb.Breakpoint):
    def __init__(self):
        super().__init__('malloc', internal=True)
    def stop(self):
        size = int(gdb.parse_and_eval('$rdi'))
        if 0x30 <= size <= 0x70 or 0x240 <= size <= 0x290:
            MallocFinish(size)
        return False
class WriteWatch(gdb.Breakpoint):
    def __init__(self, addr):
        super().__init__('*%#x' % addr, gdb.BP_WATCHPOINT, gdb.WP_WRITE, False, True)
    def stop(self):
        addr = state['target']
        new = int(gdb.parse_and_eval('*(unsigned char *)%#x' % addr))
        print('=== WRITE target=%#x old_byte=%#x new_byte=%#x ===' %
              (addr, state['old'] & 0xff, new))
        MallocProbe()
        ReadWatch(addr)
        return False
class ReadWatch(gdb.Breakpoint):
    def __init__(self, addr):
        super().__init__('*%#x' % addr, gdb.BP_WATCHPOINT, gdb.WP_READ, False, True)
    def stop(self):
        state['reads'] += 1
        if state['reads'] > 64:
            self.enabled = False
            return False
        addr = state['target']
        val = int(gdb.parse_and_eval('*(unsigned char *)%#x' % addr))
        names = []
        frame = gdb.newest_frame()
        while frame and len(names) < 12:
            names.append(frame.name() or '?')
            frame = frame.older()
        print('=== READ #%d target=%#x byte=%#x frames=%s ===' %
              (state['reads'], addr, val, ','.join(names[:10])))
        return False
class Attack(gdb.Breakpoint):
    def __init__(self):
        super().__init__('string.c:7839')
    def stop(self):
        src = int(gdb.parse_and_eval('(char *)source_current'))
        end = int(gdb.parse_and_eval('(char *)source_end'))
        if end - src != len(EXPECTED):
            return False
        if gdb.selected_inferior().read_memory(src, len(EXPECTED)).tobytes() != EXPECTED:
            return False
        buf = int(gdb.parse_and_eval('(char *)current_buffer'))
        target = buf + 24 + (len(EXPECTED) + 20)
        state['target'] = target
        state['buf'] = buf
        state['old'] = int(gdb.parse_and_eval('*(unsigned long *)%#x' % target))
        print('=== TARGET N=%d buf=%#x target=%#x old=%#x ===' %
              (len(EXPECTED), buf, target, state['old']))
        WriteWatch(target)
        return False
Attack()
end
run
bt 24
quit
