#!/usr/bin/env python3
"""Decrypt route.bin records with xorshift32 seed 1 and show VM instructions."""
import struct

M = 0xffffffff

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
    off = 8
    recs = []
    while off < len(d):
        cnt = struct.unpack_from('<H', d, off)[0]
        off += 2
        recs.append(d[off:off + cnt * 8])
        off += cnt * 8
    return recs

if __name__ == '__main__':
    recs = parse_route()
    ks = keystream(1, max(len(r) for r in recs))
    for i, r in enumerate(recs):
        dec = bytes(a ^ b for a, b in zip(r, ks[:len(r)]))
        print(f'=== rec{i} len={len(dec)} ({len(dec)//8} instrs)')
        for k in range(len(dec) // 8):
            e = dec[8 * k:8 * k + 8]
            op, tag = e[0], e[1]
            C = int.from_bytes(e[2:4], 'little')
            imm = int.from_bytes(e[4:8], 'little')
            print('  %2d: op=%-2d tag=%-3d C=%-6d imm=0x%08x' % (k, op, tag, C, imm))
