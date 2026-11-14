#!/usr/bin/env python3
"""Model op3 (masked insertion sort), op5 (merge by w4) for the ferry VM."""
import struct, sys
sys.path.insert(0, '.')
from vm2 import parse_route, M

def s16(x):
    x &= 0xffff
    return x - 0x10000 if x & 0x8000 else x

def sortkey(w4, key, mask):
    return ((w4 * key) & 0xffff) ^ mask

def sort_items(items, imm):
    """items: list of dict(w4, C, p0). Returns sorted by ((w4*key)^mask)."""
    key = s16(imm & 0xffff)
    mask = (imm >> 16) & 0xffff
    def k(it):
        return sortkey(it['w4'], key, mask)
    out = []
    for it in items:
        out.append(it)
        i = len(out) - 1
        while i > 0 and k(out[i]) < k(out[i - 1]):
            out[i], out[i - 1] = out[i - 1], out[i]
            i -= 1
    return out

def merge(items):
    """Merge items with equal w4 (first match wins). Returns (merged, nmerges)."""
    out, n = [], 0
    for it in items:
        hit = None
        for o in out:
            if o['w4'] == it['w4']:
                hit = o
                break
        if hit is not None:
            hit['C'] = (hit['C'] + it['C']) & 0xffff
            hit['p0'] ^= it['p0']
            n += 1
        else:
            out.append(dict(it))
    return out, n

if __name__ == '__main__':
    recs = parse_route()
    def prog(idx, seed=None):
        d = recs[idx]
        if seed is not None:

            def xs_(x):
                x &= M; x ^= (x << 13) & M; x ^= x >> 17; x ^= (x << 5) & M; return x & M
            s = seed; ks = b''
            while len(ks) < len(d):
                s = xs_(s); ks += struct.pack('<I', s)
            d = bytes(a ^ b for a, b in zip(d, ks))
        return [dict(op=d[8*k], tag=d[8*k+1], C=int.from_bytes(d[8*k+2:8*k+4],'little'),
                     imm=int.from_bytes(d[8*k+4:8*k+8],'little')) for k in range(len(d)//8)]
    p = prog(1, 0xfb408fa3)
    op3 = [x for x in p if x['op'] == 3][0]
    w4s = [(x['imm'] & 0xffff, x['imm'] >> 16) for x in p if x['op'] == 15]
    print('op3 imm=0x%08x key=%d mask=0x%x' % (op3['imm'], s16(op3['imm'] & 0xffff), (op3['imm'] >> 16) & 0xffff))
    print('w4/ C pairs:', [(hex(a), hex(b)) for a, b in w4s])
    print('sort keys:', [(hex(a), hex(sortkey(a, s16(op3['imm'] & 0xffff), (op3['imm'] >> 16) & 0xffff))) for a, _ in w4s])
    order = sorted(w4s, key=lambda t: sortkey(t[0], s16(op3['imm'] & 0xffff), (op3['imm'] >> 16) & 0xffff))
    print('sorted order:', [(hex(a), hex(b)) for a, b in order])
    op7 = [x for x in p if x['op'] == 7][0]
    print('op7 first w4=0x%x last w4=0x%x' % (op7['imm'] & 0xffff, op7['imm'] >> 16))
