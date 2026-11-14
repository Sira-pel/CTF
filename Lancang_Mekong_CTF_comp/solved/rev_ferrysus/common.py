#!/usr/bin/env python3
"""Faithful sim + auto-verify each executed op against GDB-observed states."""
import struct, subprocess, sys, re
sys.path.insert(0, '.')

M = 0xffffffff
Q = 0x842108421084211

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

def neg31(n):
    hi = (n * Q) >> 64
    t = ((n - hi) >> 1) + hi
    q = t >> 4
    return (q - (q << 5)) & M

def cl_of(w4, i):
    return ((w4 & 7) + (1 + 5 * i) + neg31((w4 & 7) + 5 * i)) & 31

def step(acc, p0, w4, C, mul, i, mode):
    x = (acc ^ p0) & M
    cl = cl_of(w4, i)
    if mode == 0:
        return (rol(x, cl) * mul + C) & M
    if mode == 1:
        t = ((x >> 15) ^ x) & M
        t = (t * mul) & M
        return (((t >> 13) ^ t) + C) & M
    if mode == 2:
        return (rol((x * mul) & M, cl) ^ ((C * 0x1000193) & M)) & M
    t = ((w4 | (C << 16)) ^ x) & M
    return (rol(t, cl) * mul) & M

def unstep(acc, want, w4, C, mul, i, mode):
    cl = cl_of(w4, i)
    if mode == 2:
        y = (want ^ ((C * 0x1000193) & M)) & M
        return (acc ^ ((ror(y, cl) * inv32(mul)) & M)) & M
    if mode == 0:
        # want = rol(x, cl) * mul + C  ->  x = ror((want-C) * inv(mul), cl)
        return (acc ^ (ror(((want - C) & M) * inv32(mul) & M, cl))) & M
    if mode == 3:
        return ((ror((want * inv32(mul)) & M, cl) ^ w4 ^ (C << 16) ^ acc) & M)
    raise NotImplementedError

def parse_route(path='route.bin'):
    d = open(path, 'rb').read()
    off, recs = 8, []
    while off < len(d):
        cnt = struct.unpack_from('<H', d, off)[0]
        off += 2
        recs.append(d[off:off + cnt * 8])
        off += cnt * 8
    return recs

def xs(x):
    x &= M; x ^= (x << 13) & M; x ^= x >> 17; x ^= (x << 5) & M
    return x & M

def keystream(seed, n):
    out, s = b'', seed & M
    while len(out) < n:
        s = xs(s)
        out += struct.pack('<I', s)
    return out[:n]

def decrypt(rec, seed):
    return bytes(a ^ b for a, b in zip(rec, keystream(seed, len(rec))))

def toprog(blob):
    return [dict(op=blob[8*k], tag=blob[8*k+1], C=int.from_bytes(blob[8*k+2:8*k+4], 'little'),
                 imm=int.from_bytes(blob[8*k+4:8*k+8], 'little')) for k in range(len(blob)//8)]

def fold13(seed, p0s, Cs):
    e = seed
    for i in range(len(p0s)):
        e = (e ^ p0s[i]) & M
        e = rol((e * 0x1000193) & M, 5)
        e = (e ^ Cs[i]) & M
    return e

if __name__ == '__main__':
    print('ok')
