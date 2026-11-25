"""Send one mcumgr image-upload SMP packet to the native loopback listener.

Usage: python3 client.py PORT IH_HDR_SIZE
The payload is a real MCUboot image header, an encrypted-image body and a
valid IMAGE_TLV_INFO_MAGIC block at BOOT_TLV_OFF(hdr) = hdr + ih_img_size,
so the pinned read_image_size() succeeds and decrypt_image_inplace() runs.
"""
import socket
import struct
import sys

port, hdr = int(sys.argv[1]), int(sys.argv[2])
IMG_SIZE = 8192
tlv_off = hdr + IMG_SIZE
assert tlv_off + 8 <= 32768
head = struct.pack("<IIHHII", 0x96F3B83D, 0, hdr, 0, IMG_SIZE, 4) + b"\x00" * 12
assert len(head) == 32
image = head + b"\xcc" * (tlv_off - len(head)) + struct.pack("<HH", 0x6907, 8)
payload = bytes([0xA4])
payload += bytes([0x65]) + b"image" + bytes([0x00])
payload += bytes([0x64]) + b"data"
payload += bytes([0x5A]) + struct.pack(">I", len(image)) + image
payload += bytes([0x63]) + b"len" + bytes([0x1A]) + struct.pack(">I", len(image))
payload += bytes([0x63]) + b"off" + bytes([0x00])
smp = bytes([0x02, 0x00]) + struct.pack(">HH", len(payload), 1) + bytes([0x00, 0x01])
s = socket.create_connection(("127.0.0.1", port), timeout=15)
s.sendall(smp + payload)
s.sendall(b"WIRE-CHOICE-1234")
s.close()
