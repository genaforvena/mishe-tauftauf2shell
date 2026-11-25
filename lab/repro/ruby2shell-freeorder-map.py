#!/usr/bin/env python3
"""Full-trace free-order/physical-neighbor map for routed 1000-byte plants.

The stock Rails driver (ruby2shell-shrink-claim.sh) emits unbuffered M/F lines
from lab/preload/mtrace.c plus D lines (MTRACE_FREE_DUMP=1, sizefield 0x300..
0x500) showing the chunk's user qwords immediately BEFORE free.  This tool
maps the drain/plant slice+value allocations in one such log: allocation order,
free order, physical successor, and later reuse (tcache LIFO vs unsorted FIFO
is visible in the reuse order, not in the pre-free D qwords).

Use:
  python3 lab/repro/ruby2shell-freeorder-map.py \
      lab/build/evidence/stock-rails-n972map2-1.server.log \
      --drain-parts 7 --plant-parts 4

No payload, no network, no writes to the traced process: pure log analysis.
"""
import argparse
import re
import sys

M_RE = re.compile(r'^M \d+ ([0-9a-f]+) ([0-9a-f]+) ')
F_RE = re.compile(r'^F \d+ ([0-9a-f]+) ([0-9a-f]+) ')
D_RE = re.compile(r'^D (?:0x)?([0-9a-f]+) (?:0x)?([0-9a-f]+) '
                  r'(?:0x)?([0-9a-f]+) (?:0x)?([0-9a-f]+)')

def parse(path):
    m, f, d, marks = [], {}, {}, []
    with open(path, errors='replace') as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.rstrip('\n')
            if line.startswith('M '):
                q = M_RE.match(line)
                if q:
                    m.append((lineno, int(q.group(1), 16), int(q.group(2), 16)))
            elif line.startswith('F '):
                q = F_RE.match(line)
                if q:
                    f.setdefault(int(q.group(1), 16), []).append(
                        (lineno, int(q.group(2), 16)))
            elif line.startswith('D '):
                q = D_RE.match(line)
                if q:
                    d.setdefault(int(q.group(1), 16), []).append(
                        (lineno, int(q.group(2), 16),
                         int(q.group(3), 16), int(q.group(4), 16)))
            elif line.startswith(('Started ', 'B tid=', 'A tid=')):
                marks.append((lineno, line[:110]))
    return m, f, d, marks


def first_after(seq, line):
    return next((x for x in seq if x[0] > line), None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('log')
    ap.add_argument('--slice-req', type=lambda x: int(x, 0), default=0x3f1)
    ap.add_argument('--value-req', type=lambda x: int(x, 0), default=0x400)
    ap.add_argument('--drain-parts', type=int, default=7)
    ap.add_argument('--plant-parts', type=int, default=4)
    args = ap.parse_args()
    m, f, d, marks = parse(args.log)
    drain_byte = 0x64
    plant_byte = 0x70

    def phase_of(x):
        line, _, ptr = x
        fr = first_after(f.get(ptr, []), line)
        if not fr:
            return None
        dd = next((q for q in d.get(ptr, []) if abs(q[0] - fr[0]) <= 1), None)
        if not dd:
            return None
        if dd[2] == dd[3] == drain_byte * 0x0101010101010101:
            return 'drain'
        if dd[2] == dd[3] == plant_byte * 0x0101010101010101:
            return 'plant'
        return None

    slices = [x for x in m if x[1] == args.slice_req]
    vals = [x for x in m if x[1] == args.value_req]
    drain = [x for x in slices if phase_of(x) == 'drain'][:2 * args.drain_parts]
    plant = [x for x in slices if phase_of(x) == 'plant'][:2 * args.plant_parts]
    drain_vals = [x for x in vals if phase_of(x) == 'drain'][:args.drain_parts]
    plant_vals = [x for x in vals if phase_of(x) == 'plant'][:args.plant_parts]
    if len(drain) != 2 * args.drain_parts or len(plant) != 2 * args.plant_parts:
        print(f'classified slices: drain={len(drain)}/{2 * args.drain_parts} '
              f'plant={len(plant)}/{2 * args.plant_parts}', file=sys.stderr)
        return 2
    if len(drain_vals) != args.drain_parts or len(plant_vals) != args.plant_parts:
        print(f'classified values: drain={len(drain_vals)}/{args.drain_parts} '
              f'plant={len(plant_vals)}/{args.plant_parts}', file=sys.stderr)
        return 2
    alloc = {}
    for name, phase, vphase in (('drain', drain, drain_vals),
                                ('plant', plant, plant_vals)):
        for x in phase + vphase:
            alloc[x[0]] = (name, 'slice' if x[1] == args.slice_req else 'value', x)
    all_alloc = sorted(m, key=lambda x: x[2])
    print(f'== {args.log}: slice_req={args.slice_req:#x} '
          f'value_req={args.value_req:#x} M={len(m)} F={sum(map(len, f.values()))} '
          f'D={sum(map(len, d.values()))}')
    print('phase   line   kind   ptr              chunk            free(line:size)  '
          'successor                     reuse-after-free       D(fd,bk pre-free)')
    free_rank = {}
    for line in alloc:
        phase, kind, _ = alloc[line]
        fr = first_after(f.get(alloc[line][2][2], []), line)
        if fr:
            free_rank.setdefault((phase, kind), []).append((fr[0], alloc[line][2][2]))
    for key in free_rank:
        free_rank[key] = {ptr: i + 1 for i, (_, ptr) in
                          enumerate(sorted(free_rank[key]))}
    for line in sorted(alloc):
        phase, kind, (_, req, ptr) = alloc[line]
        fr = first_after(f.get(ptr, []), line)
        chunk = ptr - 0x10
        csize = (fr[1] & ~7) if fr else (0x400 if kind == 'slice' else 0x410)
        succ_user = chunk + csize + 0x10
        succ = next((x for x in all_alloc if x[2] == succ_user), None)
        reuse = first_after([x for x in m if x[2] == ptr], fr[0]) if fr else None
        rank = str(free_rank.get((phase, kind), {}).get(ptr, '-'))
        dd = next((x for x in d.get(ptr, []) if fr and abs(x[0] - fr[0]) <= 1), None)
        ds = (f'{dd[2]:#x},{dd[3]:#x}' if dd else '-')
        fs = (f'{fr[0]}:{fr[1]:#x}' if fr else 'NO-F')
        ss = (f'{succ_user:#x}/req{succ[1]:#x}@L{succ[0]}'
              if succ else f'{succ_user:#x}/none')
        rs = (f'L{reuse[0]}/req{reuse[1]:#x}' if reuse else '-')
        print(f'{phase:6} {line:>6} {kind:5} {ptr:#016x} '
              f'{chunk:#x}+{csize:#x} rank={rank:<2} {fs:<16} {ss:<29} {rs:<21} {ds}')
    for phase in ('drain', 'plant'):
        for kind in ('slice', 'value'):
            print(f'-- {phase}/{kind}: {len(free_rank.get((phase, kind), {}))} '
                  'frees ranked 1=first-free; see rank column')
    print('-- B/A snapshots (analysis only):')
    for line, text in marks:
        if text.startswith(('B tid=', 'A tid=')):
            print(f'  L{line} {text}')


if __name__ == '__main__':
    sys.exit(main())
