"""Send one mcumgr image-upload SMP packet to the native loopback listener.

Usage: python3 client.py PORT IH_HDR_SIZE
The payload is a real MCUboot image header, an encrypted-image body and a
valid IMAGE_TLV_INFO_MAGIC block at BOOT_TLV_OFF(hdr) = hdr + ih_img_size,
so the pinned read_image_size() succeeds and decrypt_image_inplace() runs.
"""
import socket
import struct
import sys
import time

def upload_packet(chunk, off, total):
    payload = bytes([0xA4])
    payload += bytes([0x65]) + b"image" + bytes([0x00])
    payload += bytes([0x64]) + b"data"
    payload += bytes([0x5A]) + struct.pack(">I", len(chunk)) + chunk
    payload += bytes([0x63]) + b"len" + bytes([0x1A]) + struct.pack(">I", total)
    off_value = b"\x00" if off == 0 else bytes([0x1A]) + struct.pack(">I", off)
    payload += bytes([0x63]) + b"off" + off_value
    return bytes([0x02, 0x00]) + struct.pack(">HH", len(payload), 1) + bytes([0x00, 0x01]) + payload


port, hdr = int(sys.argv[1]), int(sys.argv[2])
IMG_SIZE = 8192
tlv_off = hdr + IMG_SIZE
assert tlv_off + 8 <= 32768
head = struct.pack("<IIHHII", 0x96F3B83D, 0, hdr, 0, IMG_SIZE, 4) + b"\x00" * 12
assert len(head) == 32
image = head + b"\xcc" * (tlv_off - len(head)) + struct.pack("<HH", 0x6907, 8)
fragmented = len(sys.argv) > 3
s = socket.create_connection(("127.0.0.1", port), timeout=15)
if fragmented:
    s.sendall(b"WIRE-CHOICE-1234")
    packets = [upload_packet(image[off:off + 400], off, len(image))
               for off in range(0, len(image), 400)]
    fragments = 0
    for packet in packets:
        assert len(packet) <= 513
        chunks = [packet[:1], packet[1:2], packet[2:3], packet[3:8], packet[8:13]]
        chunks.extend(packet[i:i + 97] for i in range(13, len(packet), 97))
        for chunk in chunks:
            s.sendall(chunk)
            time.sleep(0.002)
        fragments += len(chunks)
    s.shutdown(socket.SHUT_WR)
    response = b""
    while True:
        part = s.recv(4096)
        if not part:
            break
        response += part
    print(f"CLIENT_PACKETS={len(packets)} CLIENT_FRAGMENTS={fragments} RESPONSE_BYTES={len(response)}")
else:
    s.sendall(upload_packet(image, 0, len(image)))
    s.sendall(b"WIRE-CHOICE-1234")
s.close()
