#!/usr/bin/env python3
"""Solve ferry stage constraints from a route record."""
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

def parse_route(path='route.bin'):
    d = open(path, 'rb').read()
    off, recs = 8, []
    while off < len(d):
        cnt = struct.unpack_from('<H', d, off)[0]
        off += 2
        recs.append(d[off:off + cnt * 8])
        off += cnt * 8
    return recs

def items(rec):
    """Route records store items as: op, tag, C(u16), imm(u32)."""
    out = []
    for k in range(len(rec) // 8):
        e = rec[8 * k:8 * k + 8]
        out.append(dict(op=e[0], tag=e[1], C=int.from_bytes(e[2:4], 'little'),
                        imm=int.from_bytes(e[4:8], 'little')))
    return out

def fold(acc, p0, f4, f6, mul, i):
    cl = ((f4 & 7) + 5 * i) % 31 + 1
    return (rol(((acc ^ p0) * mul) & M, cl) ^ ((f6 * 0x1000193) & M)) & M

def unfold(acc, want, f4, f6, mul, i):
    cl = ((f4 & 7) + 5 * i) % 31 + 1
    y = (want ^ ((f6 * 0x1000193) & M)) & M
    return ((ror(y, cl) * inv32(mul)) & M) ^ acc

def solve_stage1(rec, verbose=True):
    it = items(rec)
    w4, w6 = {}, {}
    for x in it:
        if x['op'] == 15:
            w4[x['tag']] = x['imm'] & 0xffff
            w6[x['tag']] = x['imm'] >> 16
    n = len(w4)
    exp = {}
    for x in it:
        if x['op'] == 16:
            exp[x['tag']] = x['imm']
    seed = [x for x in it if x['op'] == 9][0]['imm']
    op10 = [x for x in it if x['op'] == 10][0]
    mul = op10['imm']
    op12 = [x for x in it if x['op'] == 12][0]['imm']
    if verbose:
        print('n=%d w4=%s' % (n, [hex(w4[i]) for i in range(n)]))
        print('     w6=%s sum=0x%x' % ([hex(w6[i]) for i in range(n)], sum(w6.values()) & 0xffff))
        print('seed=0x%08x mul=0x%08x op12=0x%08x exp=%s' % (seed, mul, op12, {k: hex(v) for k, v in exp.items()}))
    p0 = []
    acc = seed
    for i in range(n):
        want = exp[i] if i in exp else op12
        v = unfold(acc, want, w4[i], w6[i], mul, i)
        p0.append(v)
        chk = fold(acc, v, w4[i], w6[i], mul, i)
        if verbose:
            print('  i=%d u32=0x%08x -> 0x%08x (want 0x%08x)%s' % (i, v, chk, want, '' if chk == want else '  <<< BAD'))
        acc = chk
    if verbose:
        print('final acc 0x%08x  op12 0x%08x' % (acc, op12))
        op13 = [x for x in it if x['op'] == 13]
        if op13:
            e = op13[0]['imm']
            for i in range(n):
                e ^= p0[i]
                e = rol((e * 0x1000193) & M, 5)
                e ^= w6[i]
                e &= M
            key = ((e ^ acc) * 0x9e3779b1) & M
            print('op13 key=0x%08x  (need 0x46455252)' % key)
    return dict(n=n, w4=w4, w6=w6, p0=p0)

if __name__ == '__main__':
    recs = parse_route()
    solve_stage1(recs[0])
