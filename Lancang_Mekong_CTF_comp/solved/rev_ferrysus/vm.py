#!/usr/bin/env python3
"""Exact model of the ferry VM for stage-1 style programs (op1..op17)."""
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

def cl_of(w4, i):
    k = 5 * i
    return ((w4 & 7) + (1 + k) + (((w4 & 7) + k) % 31)) & 31

def op10_step(acc, p0, w4, C, mul, i, mode):
    x = (acc ^ p0) & M
    cl = cl_of(w4, i)
    if mode == 2:
        return (rol((x * mul) & M, cl) ^ ((C * 0x1000193) & M)) & M
    if mode == 0:
        return (rol(x, cl) * mul + C) & M
    if mode == 1:
        t = (x ^ (x >> 15)) & M
        t = (t * mul) & M
        return (((t >> 13) ^ t) + C) & M & M
    t = ((((C << 16) & M) | w4) ^ x) & M
    return (rol(t, cl) * mul) & M

def op10_unstep(acc, want, w4, C, mul, i, mode):
    cl = cl_of(w4, i)
    if mode == 2:
        y = (want ^ ((C * 0x1000193) & M)) & M
        return acc ^ ((ror(y, cl) * inv32(mul)) & M)
    if mode == 0:
        y = ((want - C) & M)
        return acc ^ ((ror(y, cl) * inv32(mul)) & M)
    raise NotImplementedError(mode)

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
    out = []
    for k in range(len(rec) // 8):
        e = rec[8 * k:8 * k + 8]
        out.append(dict(op=e[0], tag=e[1], w0=int.from_bytes(e[2:4], 'little'),
                        imm=int.from_bytes(e[4:8], 'little')))
    return out

def solve(rec, verbose=True):
    it = items(rec)
    w4, Cv = {}, {}
    for x in it:
        if x['op'] == 15:
            w4[x['tag']] = x['imm'] & 0xffff
            Cv[x['tag']] = x['imm'] >> 16
    n = len(w4)
    exp = {x['tag']: x['imm'] for x in it if x['op'] == 16}
    seed = [x for x in it if x['op'] == 9][0]['imm']
    o10 = [x for x in it if x['op'] == 10][0]
    mul, mode = o10['imm'], o10['tag'] & 3
    tgt = [x for x in it if x['op'] == 12][0]['imm']
    if verbose:
        print('n=%d mul=0x%08x mode=%d seed=0x%08x tgt=0x%08x' % (n, mul, mode, seed, tgt))
    p0 = []
    acc = seed
    for i in range(n):
        want = exp.get(i, tgt)
        v = op10_unstep(acc, want, w4[i], Cv[i], mul, i, mode)
        p0.append(v)
        chk = op10_step(acc, v, w4[i], Cv[i], mul, i, mode)
        if verbose:
            print('  i=%d p0=0x%08x chk=0x%08x want=0x%08x %s' % (i, v, chk, want, 'OK' if chk == want else 'BAD'))
        acc = chk
    if verbose:
        print('  final=0x%08x' % acc)
    return dict(w4=w4, Cv=Cv, p0=p0, n=n)

def slot(w4, Cw, p0, D=0):
    """pass item: [0]=w4lo [1]=w4hi [2..3]=C [4..7]=p0 [8]=D [9]=chk"""
    w0 = w4 & 0xff
    w1 = (w4 >> 8) & 0xff
    chk = 0xa5 ^ w0 ^ w1
    return bytes([w0, w1]) + struct.pack('<H', Cw & 0xffff) + struct.pack('<I', p0 & 0xffffffff) + bytes([D & 0xff, chk])

def section(stage, slots, X=0, H=0):
    n = len(slots)
    assert 1 <= n <= 8
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
    s = solve(parse_route()[0])
    it = items(parse_route()[0])
    H = [x for x in it if x['op'] == 1][0]['imm'] & 0xff
    slots = [slot(s['w4'][i], s['Cv'][i], s['p0'][i]) for i in range(s['n'])]
    X = sum(s['Cv'].values()) & 0xffff
    p = build(section(1, slots, X=X, H=H))
    r = run(p)
    print('X=0x%x H=0x%x len=%d => rc=%d %r %r' % (X, H, len(p), r.returncode, r.stdout.strip(), r.stderr.strip()[:80]))
