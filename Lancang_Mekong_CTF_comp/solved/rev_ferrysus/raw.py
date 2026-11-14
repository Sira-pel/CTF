#!/usr/bin/env python3
"""Decisive test: raw 10-byte pass slot bytes -> memory layout."""
import struct, subprocess

def rawsec(stage, blobs, X=0, H=0):
    n = len(blobs)
    hdr = b'FS' + bytes([stage, n]) + struct.pack('<H', X) + bytes([H, 0])
    offs = b''.join(struct.pack('<H', 2 * n + 8 * k) for k in range(n))
    return hdr + offs + b''.join(blobs)

# one slot with distinct bytes AA BB CC DD EE FF 11 22 33 44
blob = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44])
data = b'FJ\n\x00' + rawsec(1, [blob])
open('/tmp/raw.bin', 'wb').write(data)
print(data.hex())
