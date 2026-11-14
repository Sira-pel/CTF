#!/usr/bin/env python3
"""Exact model of ferry-inspect's VM (opcodes 1..25) + stage-1 solver."""
import struct, subprocess

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

def neg31q(n):
    """Reproduce the binary's `q - 32*q` where q = n/31 via magic multiply."""
    hi = (n * MAGIC_Q) >> 64
    t = ((n - hi) >> 1) + hi
    q = t >> 4
    return (q - ((q << 5) & 0xffffffffffffffff)) & 0xffffffff

def cl_of(w4, i):
    n = (w4 & 7) + 5 * i
    return ((w4 & 7) + (1 + 5 * i) + neg31q(n)) & 31

def step(acc, p0, w4, C, mul, i, mode):
    x = (acc ^ p0) & M
    cl = cl_of(w4, i)
    if mode == 2:
        return (rol((x * mul) & M, cl) ^ ((C * 0x1000193) & M)) & M
    if mode == 0:
        return (rol(x, cl) * mul + C) & M
    if mode == 1:
        t = ((x >> 15) ^ x) & M
        t = (t * mul) & M
        return (((t >> 13) ^ t) + C) & M
    t = ((((C << 16) & M) | w4) ^ x) & M
    return (rol(t, cl) * mul) & M

def unstep(acc, want, w4, C, mul, i, mode):
    cl = cl_of(w4, i)
    if mode == 2:
        y = (want ^ ((C * 0x1000193) & M)) & M
        return (acc ^ ((ror(y, cl) * inv32(mul)) & M)) & M
    if mode == 0:
        y = (want - C) & M
        return (acc ^ ((ror(y, cl) * inv32(mul)) & M)) & M
    raise NotImplementedError('mode %d' % mode)

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

def progit(rec):
    out = []
    for k in range(len(rec) // 8):
        e = rec[8 * k:8 * k + 8]
        out.append(dict(op=e[0], tag=e[1], C=int.from_bytes(e[2:4], 'little'),
                        imm=int.from_bytes(e[4:8], 'little')))
    return out

def solve_stage(prog, verbose=True):
    w4, Cv = {}, {}
    for x in prog:
        if x['op'] == 15:
            w4[x['tag']] = x['imm'] & 0xffff
            Cv[x['tag']] = x['imm'] >> 16
    n = len(w4)
    exp = {x['tag']: x['imm'] for x in prog if x['op'] == 16}
    seed = [x for x in prog if x['op'] == 9][0]['imm']
    o10 = [x for x in prog if x['op'] == 10][0]
    mul, mode = o10['imm'], o10['tag'] & 3
    tgt = [x for x in prog if x['op'] == 12][0]['imm']
    p0 = []
    acc = seed
    for i in range(n):
        want = exp.get(i, tgt)
        v = unstep(acc, want, w4[i], Cv[i], mul, i, mode)
        p0.append(v)
        chk = step(acc, v, w4[i], Cv[i], mul, i, mode)
        if verbose:
            print('  i=%d cl=%2d p0=0x%08x chk=0x%08x want=0x%08x %s' % (
                i, cl_of(w4[i], i), v, chk, want, 'OK' if chk == want else 'BAD'))
        acc = chk
    if verbose:
        print('  final acc=0x%08x' % acc)
    return dict(n=n, w4=w4, Cv=Cv, p0=p0, acc=acc, mode=mode, mul=mul, seed=seed, tgt=tgt)

def slot(w4, C, p0, D=0):
    w0, w1 = w4 & 0xff, (w4 >> 8) & 0xff
    return bytes([w0, w1]) + struct.pack('<H', C & 0xffff) + \
           struct.pack('<I', p0 & 0xffffffff) + bytes([D & 0xff, (0xa5 ^ w0 ^ w1)])

def section(stage, slots, X=0, H=0):
    n = len(slots)
    hdr = b'FS' + bytes([stage & 0xff, n]) + struct.pack('<H', X & 0xffff) + bytes([H & 0xff, 0])
    offs = b''.join(struct.pack('<H', 2 * n + 8 * k) for k in range(n))
    return hdr + offs + b''.join(slots)

def build(*secs):
    return b'FJ\n\x00' + b''.join(secs)

def run(data, gate=None):
    open('/tmp/x.bin', 'wb').write(data)
    a = ['./ferry-inspect', 'route.bin', data.hex()]
    if gate:
        a.append(gate)
    return subprocess.run(a, capture_output=True, text=True)

if __name__ == '__main__':
    prog = progit(parse_route()[0])
    s = solve_stage(prog)
    H = [x for x in prog if x['op'] == 1][0]['imm'] & 0xff
    slots = [slot(s['w4'][i], s['Cv'][i], s['p0'][i]) for i in range(s['n'])]
    X = sum(s['Cv'].values()) & 0xffff
    p = build(section(1, slots, X=X, H=H))
    r = run(p)
    print('X=0x%x H=0x%x len=%d => rc=%d %r' % (X, H, len(p), r.returncode, r.stdout.strip()))
