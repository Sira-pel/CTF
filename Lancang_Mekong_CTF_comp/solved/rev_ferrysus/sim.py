#!/usr/bin/env python3
"""Faithful Python model of ferry-inspect's boarding-pass VM.

Memory item layout as built by the section parser (12 bytes):
    +0  p0   u32
    +4  w4   u16
    +6  C    u16
    +8  D    u8
"""
import struct, subprocess, sys

M = 0xffffffff
MASK64 = 0xffffffffffffffff
Q_MAGIC = 0x842108421084211

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

def s16(x):
    x &= 0xffff
    return x - 0x10000 if x & 0x8000 else x

def neg31(n):
    hi = (n * Q_MAGIC) >> 64
    t = ((n - hi) >> 1) + hi
    q = t >> 4
    return (q - (q << 5)) & M

class Item:
    __slots__ = ('p0', 'w4', 'C', 'D')
    def __init__(self, p0=0, w4=0, C=0, D=0):
        self.p0, self.w4, self.C, self.D = p0 & M, w4 & 0xffff, C & 0xffff, D & 0xff
    def copy(self):
        return Item(self.p0, self.w4, self.C, self.D)
    def __repr__(self):
        return 'Item(p0=0x%08x,w4=0x%04x,C=0x%04x,D=0x%02x)' % (self.p0, self.w4, self.C, self.D)

def sort_items(items, imm):
    key = s16(imm & 0xffff)
    mask = (imm >> 16) & 0xffff
    def k(it):
        return (((s16(it.w4) * key) & 0xffff) ^ mask) & 0xffff
    out = []
    for it in items:
        out.append(it)
        i = len(out) - 1
        while i > 0 and k(out[i]) < k(out[i - 1]):
            out[i], out[i - 1] = out[i - 1], out[i]
            i -= 1
    return out

def merge_items(items):
    out, nm = [], 0
    for it in items:
        prev = out[-1] if out else None
        if prev is not None and prev.w4 == it.w4:
            s = prev.C + it.C
            prev.C = 0xffff if s > 0xffff else s
            prev.p0 ^= it.p0
            nm += 1
        else:
            out.append(it.copy())
    return out, nm

def op10_step(acc, p0, w4, C, mul, i, mode):
    x = (acc ^ p0) & M
    cl = ((w4 & 7) + (1 + 5 * i) + neg31((w4 & 7) + 5 * i)) & 31
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

def op10_unstep(acc, want, w4, C, mul, i, mode):
    cl = ((w4 & 7) + (1 + 5 * i) + neg31((w4 & 7) + 5 * i)) & 31
    if mode == 2:
        y = (want ^ ((C * 0x1000193) & M)) & M
        return (acc ^ ((ror(y, cl) * inv32(mul)) & M)) & M
    if mode == 0:
        return (acc ^ ((ror((want - C) & M, cl) * inv32(mul)) & M)) & M
    if mode == 3:
        t = (ror((want * inv32(mul)) & M, cl) ^ w4 ^ (C << 16)) & M
        return (t ^ acc) & M
    t = ((want - C) & M)
    t = (t ^ (t >> 13)) & M
    t = (t * inv32(mul)) & M
    return (acc ^ (t ^ (t << 15) & M)) & M

def fold13(seed, p0s, Cs):
    e = seed
    for i in range(len(p0s)):
        e = (e ^ p0s[i]) & M
        e = rol((e * 0x1000193) & M, 5)
        e = (e ^ Cs[i]) & M
    return e

if __name__ == '__main__':
    print('module ok')
