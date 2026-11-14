#!/usr/bin/env python3
"""General ferry chain solver."""
import struct, subprocess, sys
sys.path.insert(0, '.')
from common import *
from op10m import mode_of, sub
from final import op11, inv_op11, s16

M32 = 0xffffffff

def slot(w4, C, p0, D=0):
    w0, w1 = w4 & 0xff, (w4 >> 8) & 0xff
    return bytes([w0, w1]) + struct.pack('<H', C & 0xffff) + \
           struct.pack('<I', p0 & M32) + bytes([D & 0xff, (0xa5 ^ w0 ^ w1) & 0xff])

def section(stage, slots, X, H, count=None):
    n = count if count is not None else len(slots)
    hdr = b'FS' + bytes([stage & 0xff, n]) + struct.pack('<H', X & 0xffff) + bytes([H & 0xff, 0])
    return hdr + b''.join(struct.pack('<H', 2 * n + 8 * k) for k in range(n)) + b''.join(slots)

def build(*secs):
    return b'FJ\n\x00' + b''.join(secs)

def run(data, route='route.bin'):
    open('/tmp/x.bin', 'wb').write(data)
    return subprocess.run(['./ferry-inspect', route, data.hex()], capture_output=True, text=True)

def solve(prog, pairs, regs, last, seed, verbose=False):
    o10 = [x for x in prog if x['op'] == 10][0]
    mul, tag, nib = o10['imm'], o10['tag'], o10['C'] & 0xff
    p0, ds, acc = [], [], seed
    for i, (w4, C) in enumerate(pairs):
        want = regs.get(i, last)
        md = mode_of(tag, acc)
        v = (sub(want, C, mul, cl_of(w4, i), md, w4) ^ acc) & M32
        chk = step(acc, v, w4, C, mul, i, md)
        assert chk == want, (i, hex(chk), hex(want))
        p0.append(v)
        ds.append((chk >> 28) & 0xf if nib == 1 else (chk & 0xf if nib == 2 else 0))
        acc = chk
        if verbose:
            print('    i=%d w4=0x%04x C=0x%04x p0=0x%08x D=%d' % (i, w4, C, v, ds[-1]))
    return p0, ds, acc

def stage_info(prog):
    pairs = [(x['imm'] & 0xffff, x['imm'] >> 16) for x in prog if x['op'] == 15]
    regs = {x['tag']: x['imm'] for x in prog if x['op'] == 16}
    o9 = [x for x in prog if x['op'] == 9][0]['imm']
    o12 = [x for x in prog if x['op'] == 12]
    o13 = [x for x in prog if x['op'] == 13]
    o11 = [x for x in prog if x['op'] == 11]
    o2 = [x for x in prog if x['op'] == 2]
    o1 = [x for x in prog if x['op'] == 1][0]['imm'] & 0xff
    lo, hi = (o2[0]['tag'], o2[0]['C']) if o2 else (None, None)
    return dict(pairs=pairs, regs=regs, seed=o9, o12=o12, o13=o13, o11=o11,
                H=o1, lo=lo, hi=hi)

if __name__ == '__main__':
    recs = parse_route()
    seed = 1
    secs = []
    for idx in range(len(recs)):
        blob = recs[idx] if idx == 0 else decrypt(recs[idx], seed)
        prog = toprog(blob)
        if not all(1 <= x['op'] <= 25 for x in prog):
            print('rec%d: not a program (ops=%s)' % (idx, [x['op'] for x in prog][:8]))
            break
        info = stage_info(prog)
        print('=== rec%d  pairs=%d regs=%d lo=%s hi=%s H=0x%x' % (
            idx, len(info['pairs']), len(info['regs']), info['lo'], info['hi'], info['H']))
        if not info['o12'] or not info['o13']:
            print('   no op12/op13 -> final stage?')
            break
        last = info['o12'][0]['imm']
        if info['o11']:
            last = inv_op11(last, info['o11'][0]['tag'], info['o11'][0]['C'])
        p0, ds, acc = solve(prog, info['pairs'], info['regs'], last, info['seed'], verbose=True)
        X = sum(c for _, c in info['pairs']) & 0xffff
        n = len(info['pairs'])
        lo, hi = info['lo'], info['hi']
        need = hi if hi and hi <= 8 else n
        candidates = []
        if n >= (lo or 1):
            candidates.append(([slot(info['pairs'][i][0], info['pairs'][i][1], p0[i], ds[i]) for i in range(n)], n))
        else:
            dup_extra = (lo or n) - n
            for dup in range(n):
                items = []
                for i in range(n):
                    w4, C = info['pairs'][i]
                    if i == dup:
                        items.append(slot(w4, 0, 0, ds[i]))
                        items.append(slot(w4, C, p0[i], ds[i]))
                    else:
                        items.append(slot(w4, C, p0[i], ds[i]))
                candidates.append((items, n + 1))
        ok = False
        for items, cnt in candidates:
            Xa = sum(int.from_bytes(it[2:4], 'little') for it in items) & 0xffff
            d = build(*secs, section(idx + 1, items, Xa, info['H']))
            r = run(d)
            if 'ACCEPTED' in r.stdout:
                print('*** FULL PASS ACCEPTED with %d sections' % (idx + 1))
                open('/tmp/final.bin', 'wb').write(d)
                ok = True
                break
            path = '/tmp/st%d.bin' % (idx + 1)
            open(path, 'wb').write(d)
        o12 = info['o12'][0]['imm']
        k = fold13(info['o13'][0]['imm'], p0, [c for _, c in info['pairs']])
        key = ((k ^ o12) * 0x9e3779b1) & M32
        print('   key=0x%08x  next seed=0x%08x' % (key, (key ^ 0x46455252) & M32))
        if ok:
            break
        seed = (key ^ 0x46455252) & M32
