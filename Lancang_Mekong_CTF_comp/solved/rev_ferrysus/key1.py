#!/usr/bin/env python3
"""Compute stage key from pass items and decrypt the next route record."""
import struct, sys
sys.path.insert(0, '.')
from vm2 import rol, parse_route, progit, M

INV_9377 = pow(0x9e3779b1, -1, 1 << 32)

def fold13(seed_imm, imms, Cs):
    e = seed_imm
    for i in range(len(imms)):
        e = (e ^ imms[i]) & M
        e = rol((e * 0x1000193) & M, 5)
        e = (e ^ Cs[i]) & M
    return e

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

def dec_items(rec, seed):
    ks = keystream(seed, len(rec))
    return bytes(a ^ b for a, b in zip(rec, ks))

if __name__ == '__main__':
    from st1 import solve
    prog = progit(parse_route()[0])
    s = solve(prog, verbose=False)
    n = s['n']
    imms = [s['p0'][i] for i in range(n)]
    Cs = [s['Cv'][i] for i in range(n)]
    op13 = [x for x in prog if x['op'] == 13][0]['imm']
    f = fold13(op13, imms, Cs)
    key = ((f ^ s['acc']) * 0x9e3779b1) & M
    print('fold=0x%08x acc=0x%08x key=0x%08x' % (f, s['acc'], key))
    seed = (key ^ 0x46455252) & M
    if seed == 0:
        seed = 1
    print('seed for next stage = 0x%08x' % seed)
    recs = parse_route()
    for idx in range(len(recs)):
        d = dec_items(recs[idx], seed)
        ops = [d[8 * k] for k in range(len(d) // 8)]
        ok = all(1 <= o <= 25 for o in ops)
        print('rec%d: ops_ok=%s ops=%s' % (idx, ok, ops[:12]))
        if ok:
            for k in range(len(d) // 8):
                e = d[8 * k:8 * k + 8]
                print('   %2d: op=%-2d tag=%-2d C=0x%04x imm=0x%08x' % (
                    k, e[0], e[1], int.from_bytes(e[2:4], 'little'), int.from_bytes(e[4:8], 'little')))
