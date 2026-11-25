#!/usr/bin/env python3
"""Plant-order sweep tabulator (wall 2026-11-25 thirteenth push).

For each stock-rails-<TAG>-<i>.server.log raw log of a poison-order arm,
answer the named question: which plant population is freed, and WHEN
relative to the upcase (B line), using the complete F/R streams
address-matched against the plant parse burst's M lines. D lines only
cover sizefields 0x300..0x500, so F lines are the ground truth for the
0x620/0x810 classes.

Corrected per-part parse model (measured on raw M streams, 2026-11-25):
each embed-legal part allocates TWO content+9 slices plus ONE
next-pow2(content+1) value buffer:
  1548B part: 2x req 0x615 (chunk 0x620, sizefield 0x621)
            + 1x req 0x800 (chunk 0x810, sizefield 0x811)
   980B part: 2x req 0x3dd (chunk 0x3f0, sizefield 0x3f1)
            + 1x req 0x400 (chunk 0x410, sizefield 0x411)
Sub-embed-floor filler parts allocate only a value buffer (req 0x200 for
400B content). Rails 'Started' lines are buffered and lost on abort, so
segmentation uses only the unbuffered M/F/R/B stream; the plant burst is
the dense cluster of content+9 slice requests after the optional drain
cluster (--drain-parts N), with the value classes taken inside the
cluster's span (renders also allocate the pow2 value classes).

Usage: python3 lab/repro/ruby2shell-sweep-order.py TAG \
           [--drain-parts N] [--plant-spec 1548x16]
"""
import glob
import re
import sys

M_RE = re.compile(r'^M (\d+) ([0-9a-f]+) ([0-9a-f]+) ')
F_RE = re.compile(r'^F (\d+) ([0-9a-f]+) ([0-9a-f]+) ')
R_RE = re.compile(r'^R ([0-9a-f]+) ([0-9a-f]+) ([0-9a-f]+) ([0-9a-f]+)')
B_RE = re.compile(r'^B tid=\d+ first_request=(0x[0-9a-f]+) .*'
                  r'victim=(0x[0-9a-f]+) size=(0x[0-9a-f]+) '
                  r'fd=(\S+) bk=(\S+)')
A_RE = re.compile(r'^A tid=\d+ .*victim=(0x[0-9a-f]+) size=(0x[0-9a-f]+) ')
ABORT_PATS = ('corrupted', 'munmap', 'malloc():', 'Assertion', 'SIGABRT',
              'invalid pointer', 'invalid next size', 'double free')

SLICE_BIG = 0x615    # 1557 = 1548 + 9
VALUE_BIG = 0x800    # 2048 = next pow2 >= 1549
SLICE_SMALL = 0x3dd  # 989 = 980 + 9
VALUE_SMALL = 0x400  # 1024 = next pow2 >= 981
SLICE_D30 = 0x61d    # 1565 = 1556 + 9 (0x630 decoy slice)
SLICE_D40 = 0x62d    # 1581 = 1572 + 9 (0x640 decoy slice)
QUOTA = {SLICE_BIG: 16, VALUE_BIG: 8, SLICE_SMALL: 16, VALUE_SMALL: 8}
NAMES = {SLICE_BIG: 'big-slice(0x620)', VALUE_BIG: 'big-value(0x810)',
         SLICE_SMALL: 'small-slice(0x3f0)', VALUE_SMALL: 'small-value(0x410)',
         SLICE_D30: 'decoy630-slice', SLICE_D40: 'decoy640-slice'}
CLAIM_REQS = {0x648, 0x441}     # 1599+9, 1080+9 claim slice requests
B_GAP_MAX = 200                 # max lines between burst signature allocs
SLICE_REQS = {SLICE_BIG, SLICE_SMALL, SLICE_D30, SLICE_D40}


def npow2(v):
    p = 1
    while p < v:
        p <<= 1
    return p


def spec_classes(spec):
    """'1527x40,1517x6' -> {slice_req: (quota, value_req, name)} per class."""
    classes = {}
    for grp in spec.split(','):
        if not grp:
            continue
        size, count = (int(v, 0) for v in grp.split('x'))
        slice_req = size + 9
        value_req = npow2(size + 1)
        cls = classes.setdefault(slice_req, [0, value_req,
                                            f'slice({size}B)'])
        cls[0] += 2 * count
        # values of same-req parts accumulate on the value class
        classes.setdefault(value_req, [0, None, f'value({value_req:#x})'])
        if classes[value_req][0] == 0 and value_req != slice_req:
            classes[value_req][0] = 0
    # value quotas counted separately (one per part)
    for grp in spec.split(','):
        if not grp:
            continue
        size, count = (int(v, 0) for v in grp.split('x'))
        value_req = npow2(size + 1)
        classes[value_req][0] += count
    return classes


def spec_quota(spec):
    """plant spec -> per-req allocation quota {req: count}."""
    return {req: c[0] for req, c in spec_classes(spec).items() if c[0]}

def parse_run(path, drain_parts=0, quota=None, classes=None):
    quota = quota or QUOTA
    if classes is None:
        classes = {}
    names = {req: c[2] for req, c in classes.items()}
    names.update(NAMES)
    slice_reqs = {req for req, c in classes.items()
                  if c[2].startswith('slice')} or SLICE_REQS
    lines = open(path, errors='replace').read().splitlines()
    mlines = []
    b_idx = None
    for i, line in enumerate(lines):
        m = M_RE.match(line)
        if m:
            mlines.append((i, int(m.group(2), 16), int(m.group(3), 16)))
            continue
        if b_idx is None and line.startswith('B tid='):
            b_idx = i
    # cluster on SLICE signatures only (content+9 request sizes are
    # parse-distinctive; renders also allocate the pow2 value classes
    # 0x400/0x800 and would chain clusters across requests); value-class
    # lines inside a cluster's span belong to that cluster
    sl = [t for t in mlines if t[1] in slice_reqs]
    # cluster by gap; the PLANT parse is the densest pre-B cluster
    # (renders allocate some classes too, e.g. 0x600, so pick by size)
    clusters = []
    cur = []
    for t in sl:
        if cur and t[0] - cur[-1][0] > B_GAP_MAX:
            clusters.append(cur)
            cur = []
        cur.append(t)
    if cur:
        clusters.append(cur)
    pre_b = [c for c in clusters
             if b_idx is None or c[0][0] < b_idx]
    plant_cluster = None
    if drain_parts and len(pre_b) >= 2:
        plant_cluster = max(pre_b[:-1], key=len, default=None)
    elif pre_b:
        plant_cluster = max(pre_b, key=len)
    plant = {}
    got = {k: 0 for k in quota}
    plant_order = []
    burst_start = None
    if plant_cluster:
        lo = plant_cluster[0][0] - 50
        hi = plant_cluster[-1][0] + 50
        burst_start = plant_cluster[0][0]
        for i, req, ptr in mlines:
            if req in quota and lo <= i <= hi and got[req] < quota[req]:
                got[req] += 1
                plant.setdefault(req, []).append(ptr)
                plant_order.append((i, req, ptr))
    burst_ok = all(got[k] == quota[k] for k in quota)
    plant_all = set()
    for ptrs in plant.values():
        plant_all.update(ptrs)


    plant_alloc = {ptr: (i, req) for i, req, ptr in plant_order}
    first_free = {}   # ptr -> (idx, sizefield): first free after alloc
    reallocs = []
    pops = {'claim': [], 'probe': [], 'other': []}
    b_lines, a_lines = [], []
    for i, line in enumerate(lines):
        m = B_RE.match(line)
        if m:
            b_lines.append((int(m.group(2), 16), int(m.group(3), 16),
                            m.group(4), m.group(5), int(m.group(1), 16)))
            continue
        m = A_RE.match(line)
        if m:
            a_lines.append((int(m.group(1), 16), int(m.group(2), 16)))
            continue
        m = F_RE.match(line)
        if m:
            ptr = int(m.group(2), 16)
            if ptr in plant_alloc:
                alloc_i = plant_alloc[ptr][0]
                if i > alloc_i and ptr not in first_free:
                    first_free[ptr] = (i, int(m.group(3), 16))
            continue
        m = R_RE.match(line)
        if m:
            old = int(m.group(2), 16)
            if old in plant_all:
                reallocs.append((i, int(m.group(3), 16)))
            continue
        m = M_RE.match(line)
        if m and b_idx is not None and i > b_idx:
            req, ptr = int(m.group(2), 16), int(m.group(3), 16)
            if ptr in plant_all:
                if req in CLAIM_REQS:
                    pops['claim'].append((ptr, req))
                elif req in (SLICE_SMALL, VALUE_SMALL):
                    pops['probe'].append((ptr, req))
                else:
                    pops['other'].append((ptr, req))

    abort = ''
    for line in lines:
        if any(p in line for p in ABORT_PATS):
            abort = line.strip()[:100]
            break

    victim = b_lines[0][0] if b_lines else None
    victim_kind = 'none'
    if victim is not None:
        for req, ptrs in plant.items():
            if victim in ptrs:
                victim_kind = names.get(req, '?')
                break
        else:
            victim_kind = 'other'
    # freed at upcase: the F stream saw a free of the victim before the B
    # line (fd==bk alone false-positives on chosen content bytes)
    freed_sig = False
    if b_lines and b_idx is not None and victim in first_free:
        freed_sig = first_free[victim][0] < b_idx
    # buffer1 (the upcase's first mapping buffer): the case-request M line
    # right after the B snapshot; classify where it landed
    buf1 = None
    buf1_kind = 'none'
    if b_lines and b_idx is not None:
        for line in lines[b_idx + 1:b_idx + 10]:
            m = M_RE.match(line)
            if m and int(m.group(2), 16) == b_lines[0][4]:
                buf1 = int(m.group(3), 16)
                for req, ptrs in plant.items():
                    if buf1 in ptrs:
                        buf1_kind = names.get(req, '?')
                        break
                else:
                    buf1_kind = 'other'
                break
    return {
        'burst_ok': burst_ok, 'got': got, 'plant': plant,
        'plant_alloc': plant_alloc, 'frees': first_free,
        'reallocs': reallocs, 'pops': pops,
        'b': b_lines[0] if b_lines else None,
        'a': a_lines[0] if a_lines else None,
        'b_idx': b_idx, 'nb': len(b_lines),
        'victim': victim, 'victim_kind': victim_kind,
        'buf1': buf1, 'buf1_kind': buf1_kind,
        'freed_sig': freed_sig, 'abort': abort,
        'names': names,
    }

def main():
    tag = sys.argv[1]
    drain_parts = 0
    quota = QUOTA
    classes = {}
    args = sys.argv[2:]
    k = 0
    while k < len(args):
        if args[k] == '--drain-parts':
            drain_parts = int(args[k + 1])
            k += 2
        elif args[k] == '--plant-spec':
            quota = spec_quota(args[k + 1])
            classes = spec_classes(args[k + 1])
            k += 2
        else:
            k += 1
    runs = 0
    freed_by_kind = {}
    pops_tot = {'claim': 0, 'probe': 0, 'other': 0}
    vic = {}
    freed_vic = grown = aborts = burst_bad = realloc_tot = 0
    for path in sorted(glob.glob(f'lab/build/evidence/stock-rails-{tag}-*.server.log'),
                       key=lambda p: int(re.search(r'-(\d+)\.server\.log$', p).group(1))):
        r = parse_run(path, drain_parts, quota, classes)
        run_id = re.search(r'-(\d+)\.server\.log$', path).group(1)
        if not r['burst_ok']:
            print(f"run {run_id:>2}: PLANT BURST INCOMPLETE {r['got']} "
                  f"{'ABORT: ' + r['abort'][:50] if r['abort'] else ''}")
            burst_bad += 1
            runs += 1
            continue
        runs += 1
        preb = {'big': 0, 'small': 0}
        postb = {'big': 0, 'small': 0}
        detail = []
        for ptr, (i, szf) in r['frees'].items():
            req = r['plant_alloc'][ptr][1]
            kind = 'big' if req in (SLICE_BIG, VALUE_BIG) else 'small'
            when = 'pre-B' if (r['b_idx'] is None or i < r['b_idx']) \
                else 'post-B'
            if when == 'pre-B':
                preb[kind] += 1
            else:
                postb[kind] += 1
            detail.append((r['names'].get(req, hex(req)), when, hex(szf)))
            key = (kind, when)
            freed_by_kind[key] = freed_by_kind.get(key, 0) + 1
        bsz = f"{r['b'][1]:#x}" if r['b'] else '-'
        asz = f"->{r['a'][1]:#x}" if r['a'] else ''
        print(f"run {run_id:>2}: frees big pre/post={preb['big']}/{postb['big']} "
              f"small pre/post={preb['small']}/{postb['small']} "
              f"buf1={r['buf1_kind']} "
              f"victim={r['victim_kind']}{'/freed' if r['freed_sig'] else ''} "
              f"b={bsz}{asz} "
              f"{'ABORT: ' + r['abort'][:55] if r['abort'] else ''}")
        if detail:
            print(f"          plant frees: {detail[:16]}"
                  f"{' ...' if len(detail) > 16 else ''}")
        for k in ('claim', 'probe', 'other'):
            if r['pops'][k]:
                print(f"          {k} pops of plant addrs: "
                      f"{[(hex(p), hex(q)) for p, q in r['pops'][k]][:8]}")
                pops_tot[k] += len(r['pops'][k])
        if r['reallocs']:
            print(f"          reallocs of plant addrs: {r['reallocs'][:8]}")
            realloc_tot += len(r['reallocs'])
        vic[r['victim_kind']] = vic.get(r['victim_kind'], 0) + 1
        if r['freed_sig']:
            freed_vic += 1
        if r['a'] and r['b'] and r['a'][1] == (r['b'][1] & ~0xff) | 0x53:
            grown += 1
        if r['abort']:
            aborts += 1
    print(f"== {tag}: runs={runs} (burst-incomplete={burst_bad})")
    print(f"   victim kinds: {vic}")
    print(f"   plant frees: {freed_by_kind}")
    print(f"   freed-sig victims={freed_vic} grown={grown} aborts={aborts}")
    print(f"   post-B pops of plant addrs: {pops_tot}; "
          f"reallocs={realloc_tot}")


if __name__ == '__main__':
    main()
