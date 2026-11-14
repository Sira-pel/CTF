#!/usr/bin/env python3
"""Minimal ferry pass builder (10-byte items, offset table)."""
import struct, subprocess, sys

def item(op, tag=0, C=0, imm=0, D=0):
    b = bytes([op & 0xff, tag & 0xff]) + struct.pack('<H', C & 0xffff) + struct.pack('<I', imm & 0xffffffff)
    return b + bytes([D & 0xff, (0xa5 ^ op ^ tag) & 0xff])

def section(stage, items, X=0, H=0x7c):
    n = len(items)
    hdr = b'FS' + bytes([stage & 0xff, n & 0xff]) + struct.pack('<H', X) + bytes([H & 0xff, 0])
    offs = b''.join(struct.pack('<H', 2 * n + 10 * k) for k in range(n))
    return hdr + offs + b''.join(items)

def build(*secs):
    return b'FJ\n\x00' + b''.join(secs)

def test(data, tag='', gate=None, show=False):
    open('/tmp/p.bin', 'wb').write(data)
    a = ['./ferry-inspect', 'route.bin', data.hex()]
    if gate: a.append(gate)
    p = subprocess.run(a, capture_output=True, text=True)
    print('[%s] len=%d rc=%d %r %r' % (tag, len(data), p.returncode, p.stdout.strip(), p.stderr.strip()[:100]))
    if show: print('  hex:', data.hex())
    return p

if __name__ == '__main__':
    test(build(section(1, [item(1, imm=0x7c), item(8)])), 'op1+op8', show=True)
    test(build(section(1, [item(1, imm=0x7c), item(8)], H=0x00)), 'wrong-H')
