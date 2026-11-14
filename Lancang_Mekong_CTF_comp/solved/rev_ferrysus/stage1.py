#!/usr/bin/env python3
"""Analyze route record 0 (stage 1 program) and derive the pass section."""
import struct

M = 0xffffffff

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

def items(rec):
    out = []
    for k in range(len(rec) // 8):
        e = rec[8 * k:8 * k + 8]
        out.append(dict(op=e[0], tag=e[1], C=int.from_bytes(e[2:4], 'little'),
                        imm=int.from_bytes(e[4:8], 'little')))
    return out

def rol(v, n):
    n &= 31
    v &= M
    return ((v << n) | (v >> (32 - n))) & M if n else v

def op10_compute(items_, acc, mul, mode, trace=True):
    """Emulate opcode 10 (hash fold) mode&3 == 2 (as used by rec0)."""
    n = len(items_)
    r11 = 1
    k = 0
    vals = []
    for i, it in enumerate(items_):
        C = it['C']
        cl = ((C & 7) + (C & 7) + 0)  # placeholder
        x = (C & 7) + k
        cl = ((C & 7) + r11 - 31 * (x // 31)) & 0x1f
        if mode == 2:
            v = rol((acc * mul) & M, cl) ^ ((C * 0x1000193) & M)
        elif mode == 0:
            v = (rol(acc, cl) * mul + C) & M
        elif mode == 1:
            t = acc ^ (acc >> 15)
            t = (t * mul) & M
            v = ((t >> 13) ^ t) + C & M
        else:
            t = (((C >> 8) << 16) | C) ^ acc
            v = (rol(t, cl) * mul) & M
        v &= M
        vals.append(v)
        if trace:
            print('  i=%d C=0x%04x cl=%2d v=0x%08x' % (i, C, cl, v))
        acc = v
        r11 += 5
        k += 5
    return vals

if __name__ == '__main__':
    recs = parse_route()
    it = items(recs[0])
    for i, x in enumerate(it):
        print('%2d: op=%-2d tag=%-2d C=0x%04x imm=0x%08x' % (i, x['op'], x['tag'], x['C'], x['imm']))
    print()
    print('pass word4 (b0b1) / C constraints from op15/op7:')
    p = {}
    for i, x in enumerate(it):
        if x['op'] == 15:
            p.setdefault(x['tag'], {})['w4'] = x['imm'] & 0xffff
            p[x['tag']]['C'] = x['imm'] >> 16
    for k in sorted(p):
        print('  pass[%d]: b0b1=0x%04x C=0x%04x' % (k, p[k]['w4'], p[k]['C']))
    print('X =', hex(sum(p[k]['C'] for k in p)))
    regs = {}
    for x in it:
        if x['op'] == 16:
            regs[x['tag']] = x['imm']
    print('regs:', {k: hex(v) for k, v in regs.items()})
    # op10
    op10 = [x for x in it if x['op'] == 10][0]
    arr = [dict(C=p[k]['C']) for k in sorted(p)]
    print('op10: tag=%d C=0x%x imm=0x%x Dfield=%d' % (op10['tag'], op10['C'], op10['imm'], op10['C'] & 0xff))
    print('compute:')
    vals = op10_compute(arr, it[14]['imm'], op10['imm'], op10['tag'] & 3)
    print('check regs:')
    for i in range(len(vals)):
        want = regs.get(i)
        print('  v%d=0x%08x reg=%s %s' % (i, vals[i], hex(want) if want is not None else None,
                                         'OK' if want is None or want == vals[i] else 'MISMATCH'))
    print('final acc=0x%08x  op12 imm=0x%08x' % (vals[-1], [x for x in it if x['op'] == 12][0]['imm']))
