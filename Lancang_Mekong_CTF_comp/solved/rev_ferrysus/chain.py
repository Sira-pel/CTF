#!/usr/bin/env python3
"""Ferry chain solver: item = [w4:2][C:2][value:4][aux:1][chk:1] in pass sections;
route records = programs, each stage computes a key that seeds the next record."""
import struct, subprocess

M = 0xffffffff

def rol(v, n):
    n &= 31; v &= M
    return ((v << n) | (v >> (32 - n))) & M if n else v

def ror(v, n):
    n &= 31; v &= M
    return ((v >> n) | (v << (32 - n))) & M if n else v

def inv32(a):
    x = 1
    for _ in range(5):
        x = (x * (2 - a * x)) & M
    return x

def xs(x):
    x &= M
    x ^= (x << 13) & M
    x ^= x >> 17
    x ^= (x << 5) & M
    return x & M

def keystream(seed, n):
    out = b''
    s = seed & M
    while len(out) < n:
        s = xs(s)
        out += struct.pack('<I', s)
    return out[:n]

def parse_route(path='route.bin'):
    d = open(path, 'rb').read()
    assert d[:4] == b'FSR2'
    off, recs = 8, []
    while off < len(d):
        cnt = struct.unpack_from('<H', d, off)[0]
        off += 2
        recs.append(d[off:off + cnt * 8])
        off += cnt * 8
    return recs

def decode(items_blob):
    """file item = op(1) tag(1) C(2) imm(4) -> dict"""
    out = []
    for k in range(len(items_blob) // 8):
        e = items_blob[8 * k:8 * k + 8]
        out.append(dict(op=e[0], tag=e[1], C=int.from_bytes(e[2:4], 'little'),
                        imm=int.from_bytes(e[4:8], 'little')))
    return out

if __name__ == '__main__':
    recs = parse_route()
    print('record sizes:', [len(r) for r in recs])
    prog = decode(recs[0])
    for i, x in enumerate(prog):
        print('%2d: op=%-2d tag=%-2d C=0x%04x imm=0x%08x' % (i, x['op'], x['tag'], x['C'], x['imm']))
