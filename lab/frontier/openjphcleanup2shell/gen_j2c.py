import struct
import sys

def be16(v): return struct.pack(">H", v)
def be32(v): return struct.pack(">I", v)

class BitWriter:
    def __init__(self):
        self.bits = []
    def put(self, value, n):
        for i in range(n - 1, -1, -1):
            self.bits.append((value >> i) & 1)
    def bytes(self):
        out = bytearray()
        for i in range(0, len(self.bits), 8):
            chunk = self.bits[i:i + 8]
            chunk += [0] * (8 - len(chunk))
            b = 0
            for bit in chunk:
                b = (b << 1) | bit
            out.append(b)
        return bytes(out)

def siz():
    body = be16(0x4000)                 # Rsiz, HT capability flag
    body += be32(2) + be32(2)           # Xsiz, Ysiz
    body += be32(0) + be32(0)           # XOsiz, YOsiz
    body += be32(2) + be32(2)           # XTsiz, YTsiz
    body += be32(0) + be32(0)           # XTOsiz, YTOsiz
    body += be16(1)                     # Csiz, one component
    body += bytes([7, 1, 1])            # Ssiz 8 bit unsigned, XRsiz, YRsiz
    return be16(0xFF51) + be16(len(body) + 2) + body

def cap():
    body = be32(0x00020000)             # Pcap, HT part bit set
    body += be16(0x0001)                # Ccap
    return be16(0xFF50) + be16(len(body) + 2) + body

def cod():
    body = bytes([0x01])                # Scod, user defined precincts
    body += bytes([0x00]) + be16(1) + bytes([0x00])   # prog LRCP, 1 layer, no mct
    body += bytes([1])                  # num decomposition levels
    body += bytes([4, 4])               # block width and height exponents (64)
    body += bytes([0x40])               # block style, HT cleanup
    body += bytes([1])                  # reversible 5/3 kernel
    body += bytes([0xFF])               # precinct byte, resolution 0, large
    body += bytes([0x11])               # precinct byte, resolution 1, size 2
    return be16(0xFF52) + be16(len(body) + 2) + body

def qcd():
    body = bytes([0x40])                # Sqcd, 2 guard bits, no quantization
    body += bytes([0x40, 0x40, 0x40, 0x40])  # one exponent per subband
    return be16(0xFF5C) + be16(len(body) + 2) + body

def codeblock_header(bw):
    bw.put(1, 1)        # inclusion, included in this layer
    bw.put(1, 1)        # missing MSBs unary, 0 means a single one bit
    bw.put(0, 1)        # one coding pass
    bw.put(0, 1)        # Lblock increment stop, Lblock stays 3
    bw.put(2, 3)        # cleanup length, 3 bits, value 2

def packet_res0():
    bw = BitWriter()
    bw.put(1, 1)                # packet not empty
    codeblock_header(bw)        # LL codeblock, a normal 1x1 block in a 64 tall buffer
    return bw.bytes() + bytes([0x02, 0x00])   # 2 byte cleanup, scup 2

def packet_res1():
    bw = BitWriter()
    bw.put(1, 1)                # packet not empty
    codeblock_header(bw)        # first detail subband, degenerate 1x1 codeblock
    bw.put(0, 1)                # second detail subband not included
    bw.put(0, 1)                # third detail subband not included
    return bw.bytes() + bytes([0x02, 0x00])   # cleanup for the included block

def tile(data):
    sot_body = be16(0) + be32(0) + bytes([0, 1])   # Isot, Psot patched below, TPsot, TNsot
    sot = be16(0xFF90) + be16(len(sot_body) + 2) + sot_body
    sod = be16(0xFF93)
    body = sot + sod + data
    total = len(body)
    # patch Psot, the tile part length counting from SOT
    body = body[:6] + be32(total) + body[10:]
    return body

packets = packet_res0() + packet_res1()
stream = be16(0xFF4F) + siz() + cap() + cod() + qcd() + tile(packets) + be16(0xFFD9)
open(sys.argv[1], "wb").write(stream)
