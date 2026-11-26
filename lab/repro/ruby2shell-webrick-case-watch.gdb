# Ruby2Shell stock WEBrick case-watch probe.
# Run under GDB with either:
#   --args ruby lab/repro/ruby2shell-stock-baseline.ru -s webrick
# or, from lab/build/rails-stock-app with RUBY2SHELL_WATCH_RAILS=1:
#   --args ruby bin/rails server -u webrick -b 127.0.0.1 -p "$PORT"
# Required environment: RUBY2SHELL_WATCH_N, RUBY2SHELL_WATCH_PORT.
# Optional: RUBY2SHELL_WATCH_CONTINUE=1 continues past the first external
# read; RUBY2SHELL_WATCH_RECLAIM=1 logs matching malloc returns;
# RUBY2SHELL_WATCH_DUMP_MERGE=1 dumps chunk state after consolidation.
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
gdb.execute('set environment RACK_ENV production')
gdb.execute('set environment RUBY2SHELL_STOCK_PORT %d' % port)
if os.environ.get('RUBY2SHELL_WATCH_RAILS'):
    gdb.execute('set environment RAILS_ENV production')
    gdb.execute('set environment RUBYOPT -rwebrick')
end
break abort
commands
  printf "=== ABORT ===\n"
  bt 30
  quit
end
python
import gdb
EXPECTED = b'a' + b'\xdf' * (int(os.environ['RUBY2SHELL_WATCH_N']) - 1)
state = {'target': 0, 'old': 0, 'buf': 0}
class MallocFinish(gdb.FinishBreakpoint):
    def __init__(self, size):
        super().__init__(gdb.newest_frame(), internal=True)
        self.size = size
    def stop(self):
        ret = int(gdb.parse_and_eval('$rax'))
        print('=== RECLAIM_MALLOC size=%#x ret=%#x case_buf=%#x ===' %
              (self.size, ret, state['buf']))
        return False
class MallocProbe(gdb.Breakpoint):
    def __init__(self):
        super().__init__('malloc', internal=True)
    def stop(self):
        size = int(gdb.parse_and_eval('$rdi'))
        if 0x250 <= size <= 0x280:
            MallocFinish(size)
        return False
class MergeFinish(gdb.FinishBreakpoint):
    def __init__(self, frame):
        super().__init__(frame, internal=True)
    def stop(self):
        print('=== MERGE RETURN case_buf=%#x target=%#x ===' %
              (state['buf'], state['target']))
        gdb.execute('x/24gx %#x' % (state['buf'] - 0x20))
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
        old = int(gdb.parse_and_eval('*(unsigned long *)%#x' % target))
        state['target'] = target
        state['buf'] = buf
        state['old'] = old
        print('=== TARGET N=%d buf=%#x target=%#x old=%#x ===' %
              (len(EXPECTED), buf, target, old))
        gdb.execute('x/24gx %#x' % (target - 0x30))
        WriteWatch(target)
        return False
class WriteWatch(gdb.Breakpoint):
    def __init__(self, addr):
        super().__init__('*%#x' % addr, gdb.BP_WATCHPOINT, gdb.WP_WRITE, False, True)
    def stop(self):
        addr = state['target']
        new = int(gdb.parse_and_eval('*(unsigned long *)%#x' % addr))
        print('=== WRITE target=%#x old=%#x new=%#x ===' %
              (addr, state['old'], new))
        self.enabled = False
        ReadWatch(addr)
        if os.environ.get('RUBY2SHELL_WATCH_RECLAIM'):
            MallocProbe()
        return False
class ReadWatch(gdb.Breakpoint):
    def __init__(self, addr, count=0):
        super().__init__('*%#x' % addr, gdb.BP_WATCHPOINT, gdb.WP_READ, False, True)
        self.count = count
    def stop(self):
        addr = state['target']
        new = int(gdb.parse_and_eval('*(unsigned long *)%#x' % addr))
        self.count += 1
        names = []
        frame = gdb.newest_frame()
        while frame and len(names) < 16:
            names.append(frame.name() or '?')
            frame = frame.older()
        print('=== READ #%d target=%#x value=%#x frames=%s ===' %
              (self.count, addr, new, ','.join(names[:10])))
        if 'rb_str_casemap' in names:
            self.enabled = False
            if self.count < 4:
                ReadWatch(addr, self.count)
            return False
        gdb.execute('bt 40')
        if os.environ.get('RUBY2SHELL_WATCH_DUMP_MERGE'):
            frame = gdb.newest_frame()
            while frame:
                if frame.name() == '_int_free_merge_chunk':
                    MergeFinish(frame)
                    break
                frame = frame.older()
        if os.environ.get('RUBY2SHELL_WATCH_CONTINUE'):
            self.enabled = False
            return False
        return True
Attack()
end
run
bt 40
quit
