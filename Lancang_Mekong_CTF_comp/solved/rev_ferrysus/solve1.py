#!/usr/bin/env python3
"""Solve stage 1 of ferry-inspect: derive the 8 pass items from route record 0."""
import struct

M32 = 0xffffffff

def rol(v, n):
    n &= 31
    v &= M32
    return ((v << n) | (v >> (32 - n))) & M32 if n else v

def ror(v, n):
    n &= 31
    v &= M32
    return ((v >> n) | (v << (32 - n))) & M32 if n else v

def inv32(a):
    # modular inverse mod 2^32 (a odd)
    x = 1
    for _ in range(5):
        x = (x * (2 - a * x)) & M32
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

def route_items(rec):
    out = []
    for k in range(len(rec) // 8):
        e = rec[8 * k:8 * k + 8]
        out.append(dict(imm=int.from_bytes(e[0:4], 'little'), op=e[4], tag=e[5],
                        C=int.from_bytes(e[6:8], 'little')))
    return out

def op10_fold(acc, imms, Cs, mul):
    v = acc
    for i in range(len(imms)):
        cl = ((Cs[i] & 7) + 1 + 5 * i) % 31
        v = rol(((v ^ imms[i]) * mul) & M32, cl) ^ ((Cs[i] * 0x1000193) & M32)
        v &= M32
    return v

def op10_unfold(prev_acc, target, C, mul, i):
    """invert one op10 step: find imm"""
    cl = ((C & 7) + 1 + 5 * i) % 31
    t = (ror(target ^ ((C * 0x1000193) & M32), cl) * inv32(mul)) & M32
    return t ^ prev_acc

def op13_fold(seed_imm, imms, Cs):
    e = seed_imm
    for i in range(len(imms)):
        e ^= imms[i]
        e = rol((e * 0x1000193) & M32, 5)
        e ^= Cs[i]
        e &= M32
    return e

if __name__ == '__main__':
    it = route_items(parse_route()[0])
    # gather op15 (w0, C) and op16 knownvals, op9 seed, op10 params, op12 target
    w0, Cv = {}, {}
    for x in it:
        if x['op'] == 15:
            w0[x['tag']] = x['imm'] & 0xffff
            Cv[x['tag']] = x['imm'] >> 16
    n = len(w0)
    known = {}
    for x in it:
        if x['op'] == 16:
            known[x['tag']] = x['imm']
    seed = [x for x in it if x['op'] == 9][0]['imm']
    op10 = [x for x in it if x['op'] == 10][0]
    target = [x for x in it if x['op'] == 12][0]['imm']
    Cs = [Cv[i] for i in range(n)]
    print('w0 =', [hex(w0[i]) for i in range(n)])
    print('C  =', [hex(c) for c in Cs], 'sum=0x%x' % (sum(Cs) & 0xffff))
    print('seed=0x%08x mul=0x%08x target=0x%08x known=%s' % (
        seed, op10['imm'], target, {k: hex(v) for k, v in known.items()}))

    # targets per item: knownvals for i in 0..len(known)-1, else final target
    imms = []
    acc = seed
    for i in range(n):
        tg = known[i] if i in known else target
        imm = op10_unfold(acc, tg, Cs[i], op10['imm'], i)
        imms.append(imm)
        acc = op10_fold(acc, [imm], [Cs[i]], op10['imm']) if False else None
        # recompute properly
        cl = ((Cs[i] & 7) + 1 + 5 * i) % 31
        acc = rol(((acc ^ imm) * op10['imm']) & M32, cl) ^ ((Cs[i] * 0x1000193) & M32)
        acc &= M32
        print('  i=%d imm=0x%08x -> acc=0x%08x (want %s)' % (i, imm, acc, hex(tg)))
    print('final acc 0x%08x' % acc)

    # verify with a straight fold
    print('verify fold:', hex(op10_fold(seed, imms, Cs, op10['imm'])))

    # op13 key check
    op13 = [x for x in it if x['op'] == 13][0]
    fold = op13_fold(op13['imm'], imms, Cs)
    key = ((fold ^ acc) * 0x9e3779b1) & M32
    print('op13 fold=0x%08x key=0x%08x  want 0x46455252' % (fold, key))
