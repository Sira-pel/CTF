#!/usr/bin/env python3
"""Build pass sections from inverted stage-1 constraints and test combinations."""
import struct, subprocess, itertools, sys
sys.path.insert(0, '.')
from vm2 import rol, ror, inv32, cl_of, step, unstep, parse_route, progit, M

def fold13(seed_imm, imms, Cs):
    e = seed_imm
    for i in range(len(imms)):
        e = (e ^ imms[i]) & M
        e = rol((e * 0x1000193) & M, 5)
        e = (e ^ Cs[i]) & M
    return e

def stage_items(prog):
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
    p0, aux, acc = [], [], seed
    for i in range(n):
        want = exp.get(i, tgt)
        v = unstep(acc, want, w4[i], Cv[i], mul, i, mode)
        p0.append(v)
        acc = step(acc, v, w4[i], Cv[i], mul, i, mode)
        assert acc == want, (i, hex(acc), hex(want))
        aux.append((acc >> 28) & 0xf)
    op13 = [x for x in prog if x['op'] == 13]
    key = None
    if op13:
        f = fold13(op13[0]['imm'], p0, [Cv[i] for i in range(n)])
        key = ((f ^ acc) * 0x9e3779b1) & M
    return dict(n=n, w4=w4, Cv=Cv, p0=p0, aux=aux, acc=acc, key=key,
                H=[x for x in prog if x['op'] == 1][0]['imm'] & 0xff)

def slot(w4, C, imm, aux, chk=None):
    w0, w1 = w4 & 0xff, (w4 >> 8) & 0xff
    c = (0xa5 ^ w0 ^ w1) if chk is None else chk
    return bytes([w0, w1]) + struct.pack('<H', C & 0xffff) + \
           struct.pack('<I', imm & 0xffffffff) + bytes([aux & 0xff, c])

def section(stage, slots, X, H):
    n = len(slots)
    hdr = b'FS' + bytes([stage & 0xff, n]) + struct.pack('<H', X & 0xffff) + bytes([H & 0xff, 0])
    offs = b''.join(struct.pack('<H', 2 * n + 8 * k) for k in range(n))
    return hdr + offs + b''.join(slots)

def build(*secs):
    return b'FJ\n\x00' + b''.join(secs)

def run(data):
    open('/tmp/x.bin', 'wb').write(data)
    return subprocess.run(['./ferry-inspect', 'route.bin', data.hex()], capture_output=True, text=True)

if __name__ == '__main__':
    s = stage_items(progit(parse_route()[0]))
    print('key=0x%08x H=0x%x' % (s['key'], s['H']))
    print('w4:', [hex(s['w4'][i]) for i in range(s['n'])])
    print('C :', [hex(s['Cv'][i]) for i in range(s['n'])])
    print('p0:', [hex(v) for v in s['p0']])
    print('aux:', s['aux'])
    print('sum C = 0x%x' % (sum(s['Cv'].values()) & 0xffff))
    base = [slot(s['w4'][i], s['Cv'][i], s['p0'][i], s['aux'][i]) for i in range(s['n'])]
    best = None
    for st in range(1, 11):
        for X in [sum(s['Cv'].values()) & 0xffff, 0, 1, 0x7c]:
            d = build(section(st, base, X, s['H']))
            r = run(d)
            out = r.stdout.strip()
            if 'ACCEPT' in out:
                print('ACCEPTED st=%d X=0x%x' % (st, X)); best = (st, X)
            elif out != 'BOARDING PASS REJECTED':
                print('st=%d X=0x%x -> rc=%d %r' % (st, X, r.returncode, out))
    print('done', best)
