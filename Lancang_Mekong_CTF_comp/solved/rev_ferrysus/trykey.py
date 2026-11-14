#!/usr/bin/env python3
"""Try decrypting route records with a xorshift32 keystream from plausible keys."""
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

def show(dec, tag):
    ok = all(1 <= dec[8 * k + 4] <= 25 for k in range(len(dec) // 8))
    print(f'[{tag}] len={len(dec)} ops_ok={ok}')
    if ok:
        for k in range(len(dec) // 8):
            e = dec[8 * k:8 * k + 8]
            print('   %2d: op=%-2d tag=%-3d C=%-5d imm=0x%08x   %s' % (
                k, e[0], e[1], int.from_bytes(e[2:4], 'little'), int.from_bytes(e[4:8], 'little'), e.hex(' ')))

recs = parse_route()
for seed in [0x46455252, 1, 0x9e3779b1]:
    for i in [0]:
        dec = bytes(a ^ b for a, b in zip(recs[i], keystream(seed, len(recs[i]))))
        show(dec, f'rec{i} seed=0x{seed:08x}')
