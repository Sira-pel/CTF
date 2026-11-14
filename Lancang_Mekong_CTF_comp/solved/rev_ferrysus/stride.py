#!/usr/bin/env python3
"""Try different pass item strides/offset tables."""
import struct, subprocess, sys

def mkpass(stage, items_blob, offsets, X=0, H=0x7c, count=None):
    n = count if count is not None else len(offsets)
    hdr = b'FS' + bytes([stage, n]) + struct.pack('<H', X) + bytes([H, 0])
    offs = b''.join(struct.pack('<H', o) for o in offsets)
    return b'FJ\n\x00' + hdr + offs + items_blob

def it10(op, tag=0, C=0, imm=0, D=0, chk=None):
    b = bytes([op, tag]) + struct.pack('<H', C) + struct.pack('<I', imm) + bytes([D])
    c = (0xa5 ^ op ^ tag) if chk is None else chk
    return b + bytes([c])

def it8(op, tag=0, C=0, imm=0, D=0):
    return bytes([op, tag]) + struct.pack('<H', C) + struct.pack('<I', imm)

CASES = {
    'A_stride10': mkpass(1, it10(8) + it10(8), [4, 14]),
    'B_stride8': mkpass(1, it8(8) + it8(8), [4, 12]),
    'C_single': mkpass(1, it10(8), [2]),
    'D_single_off8': mkpass(1, b'\xff' * 8 + it10(8), [8], count=1),
}
if __name__ == '__main__':
    for k, v in CASES.items():
        open(f'/tmp/{k}.bin', 'wb').write(v)
        print(k, len(v), v.hex())
