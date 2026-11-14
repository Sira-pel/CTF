#!/usr/bin/env python3
"""Ferry VM stage solver (handles op1..op17 incl. sort/merge)."""
import struct, subprocess, sys, itertools
sys.path.insert(0, '.')

M = 0xffffffff
MAGIC_Q = 0x842108421084211

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
    out, s = b'', seed & M
    while len(out) < n:
        s = xs(s)
        out += struct.pack('<I', s)
    return out[:n]

def parse_route(path='route.bin'):
    d = open(path, 'rb').read()
    off, recs = 8, []
    while off < len(d):
        cnt = struct.unpack_from('<H', d, off)[0]
        off += 2
        recs.append(d[off:off + cnt * 8])
        off += cnt * 8
    return recs

def decrypt(rec, seed):
    return bytes(a ^ b for a, b in zip(rec, keystream(seed, len(rec))))

def toprog(blob):
    return [dict(op=blob[8*k], tag=blob[8*k+1],
                 C=int.from_bytes(blob[8*k+2:8*k+4], 'little'),
                 imm=int.from_bytes(blob[8*k+4:8*k+8], 'little'))
            for k in range(len(blob)//8)]

def neg31q(n):
    hi = (n * MAGIC_Q) >> 64
    t = ((n - hi) >> 1) + hi
    q = t >> 4
    return (q - ((q << 5) & 0xffffffffffffffff)) & 0xffffffff

def cl_of(w4, i):
    return ((w4 & 7) + (1 + 5*i) + neg31q((w4 & 7) + 5*i)) & 31

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
    elif mode == 0:
        y = (want - C) & M
        return (acc ^ ((ror(y, cl) * inv32(mul)) & M)) & M
    elif mode == 3:
        t = (ror((want * inv32(mul)) & M, cl) ^ w4 ^ (C << 16)) & M
        return (t ^ acc) & M
    else:
        raise NotImplementedError('mode %d' % mode)
    return (acc ^ ((ror(y, cl) * inv32(mul)) & M)) & M

def fold13(seed_imm, imms, Cs):
    e = seed_imm
    for i in range(len(imms)):
        e = (e ^ imms[i]) & M
        e = rol((e * 0x1000193) & M, 5)
        e = (e ^ Cs[i]) & M
    return e

def op11(acc, tag, c):
    return (rol(acc, tag) ^ rol(acc, c) ^ acc) & M

def s16(x):
    x &= 0xffff
    return x - 0x10000 if x & 0x8000 else x

def slot(w4, C, imm, D=0):
    w0, w1 = w4 & 0xff, (w4 >> 8) & 0xff
    return bytes([w0, w1]) + struct.pack('<H', C & 0xffff) + \
           struct.pack('<I', imm & 0xffffffff) + bytes([D & 0xff, (0xa5 ^ w0 ^ w1)])

def section(stage, slots, X, H):
    n = len(slots)
    hdr = b'FS' + bytes([stage & 0xff, n]) + struct.pack('<H', X & 0xffff) + bytes([H & 0xff, 0])
    offs = b''.join(struct.pack('<H', 2*n + 8*k) for k in range(n))
    return hdr + offs + b''.join(slots)

def build(*secs):
    return b'FJ\n\x00' + b''.join(secs)

def run(data):
    open('/tmp/x.bin', 'wb').write(data)
    return subprocess.run(['./ferry-inspect', 'route.bin', data.hex()], capture_output=True, text=True)

if __name__ == '__main__':
    recs = parse_route()
    p1 = toprog(recs[0])
    # stage 1 known-good from earlier work
    print('rec0 ops:', [x['op'] for x in p1])
    p2 = toprog(decrypt(recs[1], 0xfb408fa3))
    for i, x in enumerate(p2):
        print('%2d: op=%-2d tag=%-3d C=0x%04x imm=0x%08x' % (i, x['op'], x['tag'], x['C'], x['imm']))
