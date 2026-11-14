#!/usr/bin/env python3
"""Craft a pass with unique marker bytes and dump what the VM stores."""
import struct, subprocess, os

def mkitems(specs):
    """specs: list of (op,tag,C,imm,D)"""
    out = b''
    for (op, tag, C, imm, D) in specs:
        out += bytes([op & 0xff, tag & 0xff]) + struct.pack('<H', C & 0xffff) + \
               struct.pack('<I', imm & 0xffffffff) + bytes([D & 0xff])
        out += bytes([(0xa5 ^ op ^ tag) & 0xff])
    return out

def mkpass(sections):
    """sections: list of (stage, X, H, specs)"""
    body = b''
    for (stage, X, H, specs) in sections:
        n = len(specs)
        body += b'FS' + bytes([stage, n]) + struct.pack('<H', X) + bytes([H, 0])
        body += b''.join(struct.pack('<H', 2 * n + 10 * k) for k in range(n))
        body += mkitems(specs)
    return b'FJ\n\x00' + body

if __name__ == '__main__':
    specs = [(0x11 + k, 0x22, 0x3344 + k, 0xAABBCCDD + k, 0x55) for k in range(8)]
    p = mkpass([(1, 0x1178, 0x7c, specs)])
    print('pass len', len(p))
    print(p.hex())
    open('/tmp/marker.bin', 'wb').write(p)
