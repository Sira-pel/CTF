#!/usr/bin/env python3
"""Full ferry chain solver: iterate every stage, build the pass, verify."""
import struct, subprocess, sys
sys.path.insert(0, '.')
from common import (rol, ror, inv32, cl_of, neg31, step, parse_route, toprog,
                    decrypt, fold13, M)
from op10m import mode_of, sub

def op11(acc, tag, C):
    return (rol(acc, tag) ^ rol(acc, C) ^ acc) & M

def s16(x):
    x &= 0xffff
    return x - 0x10000 if x & 0x8000 else x

def slot(w4, C, p0, D=0):
    w0, w1 = w4 & 0xff, (w4 >> 8) & 0xff
    return bytes([w0, w1]) + struct.pack('<H', C & 0xffff) + \
           struct.pack('<I', p0 & M) + bytes([D & 0xff, (0xa5 ^ w0 ^ w1) & 0xff])

def section(stage, slots_, X, H):
    n = len(slots_)
    hdr = b'FS' + bytes([stage & 0xff, n]) + struct.pack('<H', X & 0xffff) + bytes([H & 0xff, 0])
    return hdr + b''.join(struct.pack('<H', 2*n + 8*k) for k in range(n)) + b''.join(slots_)

def build(*secs):
    return b'FJ\n\x00' + b''.join(secs)

def solve_stage(prog, verbose=False, preseed=True):
    pairs = [(x['imm'] & 0xffff, x['imm'] >> 16) for x in prog if x['op'] == 15]
    regs = {x['tag']: x['imm'] for x in prog if x['op'] == 16}
    o10 = [x for x in prog if x['op'] == 10][0]
    mul, tag = o10['imm'], o10['tag']
    nib = o10['C'] & 0xff
    o12 = [x for x in prog if x['op'] == 12]
    last = o12[0]['imm'] if o12 else None
    n = len(pairs)
    # sorting stage (op3) changes the execution order
    o3 = [x for x in prog if x['op'] == 3]
    order = list(range(n))
    if o3:
        k = s16(o3[0]['imm'] & 0xffff); m = (o3[0]['imm'] >> 16) & 0xffff
        order = sorted(range(n), key=lambda i: (((s16(pairs[i][0]) * k) & 0xffff) ^ m) & 0xffff)
    seed = [x for x in prog if x['op'] == 9][0]['imm']
    o11s = [x for x in prog if x['op'] == 11]
    if preseed and o11s:
        seed = op11(seed, o11s[0]['tag'], o11s[0]['C'])
    p0 = [None] * n
    ds = [0] * n
    acc = seed
    for i, si in enumerate(order):
        w4, C = pairs[si]
        want = regs.get(i, last)
        md = mode_of(tag, acc)
        cl = cl_of(w4, i)
        v = (sub(want, C, mul, cl, md, w4) ^ acc) & M
        chk = step(acc, v, w4, C, mul, i, md)
        assert chk == want, ('stage', i, hex(chk), hex(want))
        p0[si] = v
        ds[si] = (chk >> 28) & 0xf if nib == 1 else (chk & 0xf if nib == 2 else 0)
        acc = chk
        if verbose:
            print('   i=%d w4=0x%04x C=0x%04x p0=0x%08x D=0x%x' % (i, w4, C, v, ds[si]))
    o13 = [x for x in prog if x['op'] == 13]
    key = None
    if o13:
        f = fold13(o13[0]['imm'], p0, [c for _, c in pairs])
        key = ((f ^ acc) * 0x9e3779b1) & M
    o8 = [x for x in prog if x['op'] == 8]
    # op8 computes a saturating u16 sum over *all* items' C, then compares to section X.
    X = sum(c for _, c in pairs) & 0xffff
    if o8:
        X = sum(c for _, c in pairs) & 0xffff
    H = [x for x in prog if x['op'] == 1][0]['imm'] & 0xff
    st = [x for x in prog if x['op'] == 2]
    stage_id = st[0]['tag'] if st else None
    return dict(pairs=pairs, p0=p0, ds=ds, acc=acc, key=key, X=X, H=H,
                stage=stage_id, n=n, order=order)

def run(data):
    open('/tmp/x.bin', 'wb').write(data)
    return subprocess.run(['./ferry-inspect', 'route.bin', data.hex()], capture_output=True, text=True)

if __name__ == '__main__':
    recs = parse_route()
    seed = 1
    secs = []
    for idx in range(len(recs)):
        blob = decrypt(recs[idx], seed) if idx else recs[idx]
        prog = toprog(blob)
        ok = all(1 <= x['op'] <= 25 for x in prog)
        print('=== stage idx=%d ops_ok=%s' % (idx, ok))
        if not ok:
            break
        s = solve_stage(prog, verbose=True)
        print('   key=0x%08x stage=%s X=0x%x H=0x%x' % (s['key'], s['stage'], s['X'], s['H']))
        items = [slot(s['pairs'][i][0], s['pairs'][i][1], s['p0'][i], s['ds'][i]) for i in range(s['n'])]
        secs.append(section(idx + 1, items, s['X'], s['H']))
        d = build(*secs)
        r = run(d)
        print('   => rc=%d %r' % (r.returncode, r.stdout.strip()))
        open(f'/tmp/chain{idx+1}.bin', 'wb').write(d)
        if 'ACCEPTED' in r.stdout:
            print('*** SOLVED ***')
            break
        seed = (s['key'] ^ 0x46455252) & M
        if seed == 0:
            seed = 1
