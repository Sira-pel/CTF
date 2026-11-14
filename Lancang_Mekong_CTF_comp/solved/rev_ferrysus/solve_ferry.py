#!/usr/bin/env python3
"""Build a ferry boarding pass by solving each route-record VM stage."""
import math
import random
import struct
import zlib

M = 0xFFFFFFFF

def rol(x, c):
    c &= 31
    return ((x << c) | (x >> (32 - c))) & M if c else x & M

def ror(x, c):
    c &= 31
    return ((x >> c) | (x << (32 - c))) & M if c else x & M

def xs(x):
    x &= M
    x ^= (x << 13) & M
    x ^= x >> 17
    x ^= (x << 5) & M
    return x & M

def parse_route(path='route.bin'):
    d = open(path, 'rb').read()
    off = 8
    recs = []
    while off < len(d):
        cnt = struct.unpack_from('<H', d, off)[0]
        off += 2
        recs.append(d[off:off + cnt * 8])
        off += cnt * 8
    return recs

def decrypt_rec(rec, key):
    seed = (key ^ 0x46455252) & M
    if seed == 0:
        seed = 1
    s = seed
    ks = b''
    while len(ks) < len(rec):
        s = xs(s)
        ks += struct.pack('<I', s)
    return bytes(a ^ b for a, b in zip(rec, ks))

def load_prog(buf):
    prog = []
    for k in range(len(buf) // 8):
        e = buf[8 * k:8 * k + 8]
        prog.append(dict(
            op=e[0], tag=e[1],
            C=int.from_bytes(e[2:4], 'little'),
            imm=int.from_bytes(e[4:8], 'little'),
        ))
    return prog

def slot(op, tag=0, C=0, imm=0, D=0):
    b = bytes([op & 0xff, tag & 0xff]) + struct.pack('<H', C & 0xffff) + struct.pack('<I', imm & 0xffffffff) + bytes([D & 0xff])
    return b + bytes([0xa5 ^ (op & 0xff) ^ (tag & 0xff)])

def section(stage, ins, X=0, H=0):
    n = len(ins)
    hdr = b'FS' + bytes([stage & 0xff, n & 0xff]) + struct.pack('<H', X & 0xffff) + bytes([H & 0xff, 0])
    offs = b''.join(struct.pack('<H', 2 * n + 8 * k) for k in range(n))
    return hdr + offs + b''.join(ins)

def rot_count(op_tag, i):
    ecx = op_tag & 7
    rbx = 5 * i
    r11 = 1 + 5 * i
    n = ecx + rbx
    magic = 0x842108421084211
    rdx = (n * magic) >> 64
    rsi = n - rdx
    rsi = (rsi >> 1) + rdx
    rsi >>= 4
    esi = (rsi - ((rsi << 5) & M)) & M
    ecx = (ecx + r11 + esi) & M
    return ecx & 31

def inv_shr_xor(z, s):
    x = 0
    for i in range(31, -1, -1):
        bit = (z >> i) & 1
        if i + s < 32:
            bit ^= (x >> (i + s)) & 1
        x |= bit << i
    return x

def mix(acc, imm, op_tag, C, i, variant, K):
    edi = (acc ^ imm) & M
    rot = rot_count(op_tag, i)
    if variant == 0:
        edi = (rol(edi, rot) * K + C) & M
    elif variant == 1:
        eax = (edi ^ (edi >> 15)) & M
        eax = (eax * K) & M
        edi = ((eax ^ (eax >> 13)) + C) & M
    elif variant == 2:
        edi = rol((edi * K) & M, rot) ^ ((C * 0x1000193) & M)
    elif variant == 3:
        ebp = ((C << 16) | op_tag) & M
        edi = (rol(ebp ^ edi, rot) * K) & M
    else:
        raise ValueError(variant)
    return edi & M

def unmix(acc, target, op_tag, C, i, variant, K):
    KINV = pow(K, -1, 1 << 32)
    rot = rot_count(op_tag, i)
    if variant == 0:
        edi = ror(((target - C) * KINV) & M, rot)
    elif variant == 1:
        eax = inv_shr_xor((target - C) & M, 13)
        edi = inv_shr_xor((eax * KINV) & M, 15)
    elif variant == 2:
        edi = ror(target ^ ((C * 0x1000193) & M), rot)
        edi = (edi * KINV) & M
    elif variant == 3:
        ebp = ror((target * KINV) & M, rot)
        edi = ebp ^ ((C << 16) | op_tag)
    else:
        raise ValueError(variant)
    imm = (edi ^ acc) & M
    got = mix(acc, imm, op_tag, C, i, variant, K)
    if got != target:
        raise AssertionError(hex(got), hex(target), variant)
    return imm

def apply_op11(x, tag, cb):
    return rol(x, tag) ^ rol(x, cb) ^ x

def solve_op11(target, tag, cb):
    """One preimage of op11, or None."""
    def f(x):
        return apply_op11(x, tag, cb)
    A = [[(f(1 << r) >> c) & 1 for r in range(32)] for c in range(32)]
    tbits = [(target >> c) & 1 for c in range(32)]
    mat = [A[c][:] + [tbits[c]] for c in range(32)]
    rank = 0
    where = [-1] * 32
    for col in range(32):
        piv = next((r for r in range(rank, 32) if mat[r][col]), None)
        if piv is None:
            continue
        mat[rank], mat[piv] = mat[piv], mat[rank]
        where[col] = rank
        for r in range(32):
            if r != rank and mat[r][col]:
                for k in range(33):
                    mat[r][k] ^= mat[rank][k]
        rank += 1
    for r in range(rank, 32):
        if mat[r][32]:
            return None
    x = 0
    for col, w in enumerate(where):
        if w != -1 and mat[w][32]:
            x |= 1 << col
    if f(x) != (target & M):
        raise AssertionError(hex(f(x)), hex(target))
    return x

# ---- insertion sort (faithful port of 0x129a0) ----
def sort_entries(raw, edx):
    n = len(raw) // 12
    mem = bytearray(raw)
    rdi = 0
    rax = n * 12
    r9 = 12
    ecx = (edx >> 16) & 0xffff
    esi = 12
    rbx = 0
    scratch = {}

    def ld32(a):
        return struct.unpack_from('<I', mem, a)[0]
    def st32(a, v):
        struct.pack_into('<I', mem, a, v & M)
    def ld16(a):
        return struct.unpack_from('<H', mem, a)[0]
    def st16(a, v):
        struct.pack_into('<H', mem, a, v & 0xffff)
    def ld64(a):
        return struct.unpack_from('<Q', mem, a)[0]
    def st64(a, v):
        struct.pack_into('<Q', mem, a, v & ((1 << 64) - 1))

    steps = 0
    while True:
        steps += 1
        if steps > 100000:
            raise RuntimeError('sort loop')
        r8 = r9
        r9d = ld32(rbx + 0x10)
        r10 = ((edx * r9d) & M) ^ ecx
        r11 = ld16(rbx + 4)
        r11 = ((r11 * (edx & 0xffff)) & 0xffff) ^ ecx
        if (r10 & 0xffff) >= (r11 & 0xffff):
            r9 = r8 + 0xc
            esi = (esi + 0xc) & M
            rbx = r8
            if r9 == rax:
                return bytes(mem)
            continue
        r11 = ld32(rbx + 0xc)
        scratch[-8] = ld32(rbx + 0x12)
        scratch[-4] = ld16(rbx + 0x16)
        r14 = esi
        while True:
            rbx = r14
            st32(rdi + r14 + 0x8, ld32(rdi + r14 - 0x4))
            st64(rdi + rbx, ld64(rdi + r14 - 0xc))
            if rbx == 0xc:
                rbx = rbx + rdi
                st32(rdi, r11)
                st16(rbx - 0x8, r9d & 0xffff)
                st32(rbx - 0x6, scratch[-8])
                st16(rbx - 0x2, scratch[-4])
                r9 = r8 + 0xc
                esi = (esi + 0xc) & M
                rbx = r8
                if r9 == rax:
                    return bytes(mem)
                break
            ebp = ld16(rdi + rbx - 0x14)
            ebp = ((ebp * (edx & 0xffff)) & 0xffff) ^ ecx
            r14 = rbx - 0xc
            if (r10 & 0xffff) < (ebp & 0xffff):
                continue
            rbx = rbx + rdi
            r14 = r14 + rdi
            st32(r14, r11)
            st16(rbx - 0x8, r9d & 0xffff)
            st32(rbx - 0x6, scratch[-8])
            st16(rbx - 0x2, scratch[-4])
            r9 = r8 + 0xc
            esi = (esi + 0xc) & M
            rbx = r8
            if r9 == rax:
                return bytes(mem)
            break

def pack_items(items):
    raw = b''
    for w, c, imm, D in items:
        op = w & 0xff
        tag = (w >> 8) & 0xff
        raw += struct.pack('<I', imm) + bytes([op, tag]) + struct.pack('<H', c) + bytes([D & 0xff, 0, 0, 0])
    return raw

def unpack_items(raw):
    out = []
    for i in range(len(raw) // 12):
        e = raw[i * 12:(i + 1) * 12]
        imm = struct.unpack_from('<I', e, 0)[0]
        w = struct.unpack_from('<H', e, 4)[0]
        c = struct.unpack_from('<H', e, 6)[0]
        D = e[8]
        out.append((w, c, imm, D))
    return out

def dedup(items):
    out = []
    merges = 0
    for w, c, imm, D in items:
        if out and out[-1][0] == w:
            s = out[-1][1] + c
            nc = s if s <= 0xffff else 0xffff
            out[-1] = (w, nc, out[-1][2] ^ imm, out[-1][3])
            merges += 1
        else:
            out.append((w, c, imm, D))
    return out, merges

def stage1_section():
    entries = [
        (0x3b, 0x14, 0x03ab),
        (0x24, 0x23, 0x0221),
        (0xe8, 0xdf, 0x02d7),
        (0x9b, 0xc4, 0x0052),
        (0x01, 0x1d, 0x00f3),
        (0xd9, 0xaa, 0x009a),
        (0xba, 0x4d, 0x0334),
        (0x52, 0x80, 0x03c2),
    ]
    targets = [0x32cfe2f7, 0x9f98f02d, 0xefc6834a, 0xba624d4f, 0x40f36f63, 0x35606637, 0x8a6ee7f9, 0xeea53ac0]
    K = 0xabb70d31
    acc = 0x84b939c6
    ins = []
    for i, ((op, tag, C), tgt) in enumerate(zip(entries, targets)):
        ot = op | (tag << 8)
        imm = unmix(acc, tgt, ot, C, i, 2, K)
        D = (tgt >> 28) & 0xF
        ins.append(slot(op, tag, C, imm, D))
        acc = tgt
    return section(1, ins, X=0x1178, H=0x7c), acc

def stage2_section():
    final = [
        (0x73a2, 0x020e),
        (0x0b6c, 0x0147),
        (0x8665, 0x01a9),
        (0x7722, 0x017c),
        (0xd71b, 0x0227),
        (0xb540, 0x023f),
    ]
    # split slot 0 so the two halves sort to the front and merge back
    w0, C0 = final[0]
    c1, c2 = 0, C0
    items = [(w0, c1, 0, 0), (w0, c2, 0, 0)]
    for w, c in final[1:]:
        items.append((w, c, 0, 0))
    EDX = 0x4a9b2fa1
    ordered = unpack_items(sort_entries(pack_items(items), EDX))
    merged, merges = dedup(ordered)
    if merges != 1 or [(w, c) for w, c, _, _ in merged] != final:
        raise SystemExit(f'stage2 structure failed merges={merges} got={merged}')
    # which physical input (by C) is first of the pair? both C distinct
    # We'll assign imms after solving post-dedup imms.
    K = 0xea146645
    acc = 0xa58c0431
    targets = [0x39303670, 0x6ce9f2dd, 0x3401e5f8, 0x071e4dfb, 0x3cc11f83]
    post_imm = []
    post_D = []
    for i, (w, c) in enumerate(final):
        variant = (acc >> 8) & 3
        if i < len(targets):
            tgt = targets[i]
        else:
            tgt = solve_op11(0xdca6a43c, 9, 3)
            if tgt is None:
                raise SystemExit('op11 no preimage')
        imm = unmix(acc, tgt, w, c, i, variant, K)
        D = (tgt >> 28) & 0xF
        post_imm.append(imm)
        post_D.append(D)
        acc = tgt
    # map post-dedup imm/D onto the pre-sort items.
    # merged[0] is the xor of the two 0x73a2 imms; put the whole imm on whichever sorts first.
    # Find the two 0x73a2 in `ordered` and put imm on the first, 0 on the second.
    seen = False
    pre = []
    for w, c, _, _ in ordered:
        if w == w0 and not seen:
            pre.append((w, c, post_imm[0], post_D[0]))
            seen = True
        elif w == w0 and seen:
            pre.append((w, c, 0, 0))
        else:
            # find index in final
            idx = next(i for i, (ww, cc) in enumerate(final) if ww == w and cc == c)
            pre.append((w, c, post_imm[idx], post_D[idx]))
    # verify dedup imms
    got, _ = dedup(pre)
    for i, (w, c, imm, D) in enumerate(got):
        if imm != post_imm[i] or D != post_D[i]:
            raise SystemExit(f'imm map fail {i} {imm:#x} {post_imm[i]:#x}')
    ins = [slot(w & 0xff, (w >> 8) & 0xff, c, imm, D) for w, c, imm, D in pre]
    Xs = sum(c for _, c in final) & 0xffff
    sec = section(2, ins, X=Xs, H=0xc2)
    return sec, acc, Xs

def commit_hash(imms, Cs, edi0):
    """FNV-style mix over post-dedup (imm, C) pairs. Mirrors op 13."""
    count = len(imms)
    if count == 0:
        return edi0 & M
    rcx = count * 12 - 12
    magic = 0xAAAAAAAAAAAAAAAB
    rdx = ((rcx * magic) >> 64) >> 3
    edi = edi0 & M
    if ((~rdx) & 3) != 0:
        start = (rdx + 1) & 3
        for k in range(start):
            edi = (edi ^ imms[k]) & M
            edi = (Cs[k] ^ rol((edi * 0x1000193) & M, 5)) & M
    else:
        start = 0
    i = start
    if rcx >= 0x24:
        while i + 4 <= count:
            edi = (edi ^ imms[i]) & M
            ecx = rol((edi * 0x1000193) & M, 5)
            edxv = (Cs[i] ^ ecx) & M
            edxv = (edxv ^ imms[i + 1]) & M
            ecx = rol((edxv * 0x1000193) & M, 5)
            edxv = (Cs[i + 1] ^ ecx) & M
            edxv = (edxv ^ imms[i + 2]) & M
            ecx = rol((edxv * 0x1000193) & M, 5)
            edxv = (Cs[i + 2] ^ ecx) & M
            edxv = (edxv ^ imms[i + 3]) & M
            ecx = rol((edxv * 0x1000193) & M, 5)
            edi = (Cs[i + 3] ^ ecx) & M
            i += 4
    while i < count:
        edi = (edi ^ imms[i]) & M
        edi = (Cs[i] ^ rol((edi * 0x1000193) & M, 5)) & M
        i += 1
    return edi & M


def apply_sbox(acc, sbox):
    out = 0
    for i in range(8):
        out |= sbox[(acc >> (4 * i)) & 0xF] << (4 * i)
    return out & M


def inv_sbox(acc, sbox):
    inv = [None] * 16
    for i, v in enumerate(sbox):
        if inv[v] is not None:
            raise RuntimeError('sbox not bijective')
        inv[v] = i
    if any(v is None for v in inv):
        raise RuntimeError('sbox not bijective')
    out = 0
    for i in range(8):
        out |= inv[(acc >> (4 * i)) & 0xF] << (4 * i)
    return out & M


def op19_walk(table, Ds):
    """Return the final nibble op 19 tests against its bitmask."""
    count = len(Ds)
    rcx = count * 12 - 12
    if rcx < 0xC:
        eax = 0
    else:
        magic = 0xAAAAAAAAAAAAAAAB
        rdx = ((rcx * magic) >> 64) >> 3
        eax = 0
        i = 0
        rdi = (rdx + 1) & ~1
        while rdi:
            eax = table[eax & 0xF]
            eax = (eax >> ((Ds[i] * 4) & 31)) & 0xF
            eax = table[eax]
            eax = (eax >> ((Ds[i + 1] * 4) & 31)) & 0xF
            i += 2
            rdi -= 2
        if (rdx & 1) == 0:
            eax = table[eax & 0xF]
            eax = (eax >> ((Ds[i] * 4) & 31)) & 0xF
    return eax & 0xF


def solve_op19_D(table, n, imm, fixed=None):
    """Pick D bytes so op 19's final nibble is a set bit of imm."""
    fixed = dict(fixed or {})
    good = {b for b in range(16) if (imm >> b) & 1}
    if not good:
        raise RuntimeError('op19 empty mask')
    # BFS over (index, current_nibble) -> D choices 0..7
    # Replay is easier: search D left to right, state is nibble entering each entry.
    from collections import deque
    # state: (entry_index, eax_nibble_before this entry's load)
    # At the start of each entry the code loads table[eax].
    # We model entry by entry, not pairs, which matches the load/shift/mask step.
    start_eax = 0
    q = deque([(0, start_eax, [])])
    seen = {(0, start_eax)}
    while q:
        i, eax, pref = q.popleft()
        if i == n:
            if eax in good:
                if op19_walk(table, pref) != eax:
                    raise RuntimeError('op19 model mismatch')
                return pref
            continue
        if i in fixed:
            choices = [fixed[i]]
        else:
            choices = range(8)
        for d in choices:
            word = table[eax & 0xF]
            nib = (word >> ((d * 4) & 31)) & 0xF
            st = (i + 1, nib)
            if st in seen:
                continue
            seen.add(st)
            q.append((i + 1, nib, pref + [d]))
    raise RuntimeError('op19 unsat')


def forge_crc_bytes(n, target, fixed=None):
    """Bytes whose zlib/IEEE CRC-32 equals target. `fixed` maps index -> forced byte."""
    fixed = dict(fixed or {})
    free = [i for i in range(n) if i not in fixed]
    if len(free) < 4:
        raise RuntimeError(f'need 4 free D bytes, have {len(free)}')
    solve = free[-4:]
    preset = [fixed.get(i, 0) for i in range(n)]
    for i in solve:
        preset[i] = 0

    def crc(bs):
        return zlib.crc32(bytes(bs)) & M

    c0 = crc(preset)
    cols = []
    for bit in range(32):
        bb = preset[:]
        bb[solve[bit // 8]] |= 1 << (bit % 8)
        cols.append(crc(bb) ^ c0)
    rhs = c0 ^ (target & M)
    mat = []
    for r in range(32):
        mat.append([((cols[c] >> r) & 1) for c in range(32)] + [(rhs >> r) & 1])
    where = [-1] * 32
    rank = 0
    for col in range(32):
        piv = next((r for r in range(rank, 32) if mat[r][col]), None)
        if piv is None:
            continue
        mat[rank], mat[piv] = mat[piv], mat[rank]
        where[col] = rank
        for r in range(32):
            if r != rank and mat[r][col]:
                mat[r] = [a ^ b for a, b in zip(mat[r], mat[rank])]
        rank += 1
    for r in range(rank, 32):
        if mat[r][32]:
            raise RuntimeError('crc unsat')
    bits = 0
    for col, w in enumerate(where):
        if w != -1 and mat[w][32]:
            bits |= 1 << col
    out = preset[:]
    for bit in range(32):
        if (bits >> bit) & 1:
            out[solve[bit // 8]] |= 1 << (bit % 8)
    if crc(out) != (target & M):
        raise RuntimeError(f'crc forge {crc(out):#x} != {target:#x}')
    return out


def commit_key(imms, Cs, op13_imm, acc):
    h = commit_hash(imms, Cs, op13_imm)
    return ((h ^ acc) * 0x9E3779B1) & M


def _find_split(final, merges, edx):
    """Return pre-dedup items (word, C) whose sort+dedup yields `final`."""
    if merges == 0:
        return list(final)
    if merges != 1:
        raise NotImplementedError(f'merges={merges}')
    for i, (w, C) in enumerate(final):
        for c1 in range(C + 1):
            c2 = C - c1
            items = [(ww, cc) for j, (ww, cc) in enumerate(final) if j != i]
            items += [(w, c1), (w, c2)]
            raw = pack_items([(ww, cc, 0, 0) for ww, cc in items])
            ordered = unpack_items(sort_entries(raw, edx))
            got, m = dedup(ordered)
            if m == 1 and [(a, b) for a, b, _, _ in got] == final:
                return [(a, b) for a, b, _, _ in ordered]
    raise RuntimeError('no split')


def _is_prime(n):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 3, 5, 7, 11, 13, 23, 29, 31, 37):
        if a >= n:
            break
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _factor(n):
    if n == 1:
        return []
    if _is_prime(n):
        return [n]
    while True:
        c = random.randrange(1, n)
        x = y = 2
        d = 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
        if d != n:
            return _factor(d) + _factor(n // d)


def _bsgs(g, h, mod, order):
    m = math.isqrt(order) + 1
    table = {}
    e = 1
    for j in range(m):
        table[e] = j
        e = e * g % mod
    step = pow(g, m * (mod - 2), mod)
    gamma = h
    for i in range(m):
        if gamma in table:
            return i * m + table[gamma]
        gamma = gamma * step % mod
    return None


def discrete_log(base, want, mod):
    """Smallest exp >= 0 with pow(base, exp, mod) == want. mod is prime."""
    if want % mod == 1:
        return 0
    facs = _factor(mod - 1)
    rems, mods = [], []
    for f in sorted(set(facs)):
        cof = (mod - 1) // f
        g = pow(base, cof, mod)
        h = pow(want, cof, mod)
        if g == 1:
            if h != 1:
                raise RuntimeError('op24 discrete log has no solution')
            continue
        x = _bsgs(g, h, mod, f)
        if x is None or pow(g, x, mod) != h:
            raise RuntimeError('op24 bsgs failed')
        rems.append(x)
        mods.append(f)
    exp, span = 0, 1
    for r, m in zip(rems, mods):
        t = ((r - exp) * pow(span, -1, m)) % m
        exp += span * t
        span *= m
    return exp % span


def split_u32(n):
    """Factor n into a*b with 2 <= a,b < 2**32."""
    facs = _factor(n)
    a = 1
    for f in sorted(facs):
        if a * f < 2**32:
            a *= f
        else:
            break
    b = n // a
    if a < 2 or b < 2 or b >= 2**32 or a * b != n:
        raise RuntimeError(f'op25 no 32-bit split for {n:#x}')
    return a, b


def build_stage(prog, stage, gate=0):
    pins = {}
    regs = {}
    op1 = op2 = op3 = op7 = op8 = op9 = op10 = op11 = op12 = op13 = op14 = op17 = op19 = op21 = None
    op22 = op24 = op25 = None
    lanes = [0] * 8
    table18 = [0] * 16
    sbox = [0] * 16
    has_dedup = False
    has_sortcheck = False
    for ins in prog:
        op = ins['op']
        if op == 1:
            op1 = ins
        elif op == 2:
            op2 = ins
        elif op == 3:
            op3 = ins
        elif op == 4:
            has_sortcheck = True
        elif op == 5:
            has_dedup = True
        elif op == 6:
            pass
        elif op == 7:
            op7 = ins
        elif op == 8:
            op8 = ins
        elif op == 9:
            op9 = ins
        elif op == 10:
            op10 = ins
        elif op == 11:
            op11 = ins
        elif op == 12:
            op12 = ins
        elif op == 13:
            op13 = ins
        elif op == 14:
            op14 = ins
        elif op == 15:
            pins[ins['tag']] = (ins['imm'] & 0xffff, ins['imm'] >> 16)
        elif op == 16:
            regs[ins['tag']] = ins['imm']
        elif op == 17:
            op17 = ins
        elif op == 18:
            table18[ins['tag'] & 0xF] = ins['imm']
        elif op == 19:
            op19 = ins
        elif op == 20:
            base = (ins['tag'] & 1) * 8
            for k in range(8):
                sbox[base + k] = (ins['imm'] >> (4 * k)) & 0xF
        elif op == 21:
            op21 = ins
        elif op == 22:
            op22 = ins
        elif op == 23:
            half = ins['C'] & 0xff
            lane = ins['tag'] & 7
            if half == 0:
                lanes[lane] = (lanes[lane] & ~0xFFFFFFFF) | ins['imm']
            elif half == 1:
                lanes[lane] = (ins['imm'] << 32) | (lanes[lane] & 0xFFFFFFFF)
            else:
                raise RuntimeError(f'stage {stage} op23 half {half}')
        elif op == 24:
            op24 = ins
        elif op == 25:
            op25 = ins
        else:
            raise NotImplementedError(f'stage {stage} opcode {op} tag={ins["tag"]} C={ins["C"]} imm={ins["imm"]:#x}')
    # op 6 range, captured properly
    op6 = next((ins for ins in prog if ins['op'] == 6), None)
    if op1 is None or op10 is None or op12 is None or op13 is None:
        raise RuntimeError(f'stage {stage} missing core ops')
    n_after = max(pins) + 1
    for i in range(n_after):
        if i not in pins:
            raise RuntimeError(f'stage {stage} missing pin {i}')
    final = [pins[i] for i in range(n_after)]
    if op7:
        if final[0][0] != (op7['imm'] & 0xffff) or final[-1][0] != (op7['imm'] >> 16):
            raise RuntimeError(f'stage {stage} op7 mismatch')
    edx = op3['imm'] if op3 else 0
    merges = 0
    if has_dedup:
        if op6 is None:
            raise RuntimeError('dedup without op6')
        lo, hi = op6['tag'], op6['C'] & 0xff
        if lo != hi:
            raise NotImplementedError(f'merge range {lo}..{hi}')
        merges = lo
    pre_wc = _find_split(final, merges, edx)
    if op2:
        raw_n = len(pre_wc)
        if not (op2['tag'] <= raw_n <= (op2['C'] & 0xff)):
            raise RuntimeError(f'stage {stage} raw count {raw_n} not in range')
    # solve post-dedup imms / D
    K = op10['imm']
    if (K & 1) == 0:
        raise RuntimeError('op10 multiplier even')
    mode = op10['C'] & 0xff
    tag10 = op10['tag']
    acc = 0
    for ins in prog:
        if ins['op'] == 9:
            acc = ins['imm']
        elif ins['op'] == 22:
            acc = (ins['imm'] ^ (gate & M)) & M
    # fixed outputs for entries that have a register target
    fixed = {i: regs[i] for i in range(n_after) if i in regs}
    free = [i for i in range(n_after) if i not in fixed]
    if len(free) > 1:
        raise NotImplementedError(f'stage {stage} free entries {free}')
    post_out = [None] * n_after
    acc_run = acc
    if not free:
        for i, (w, c) in enumerate(final):
            variant = ((acc_run >> 8) & 3) if tag10 == 255 else (tag10 & 3)
            post_out[i] = fixed[i]
            # imm solved below; just advance acc to the fixed output
            acc_run = fixed[i]
        final_acc = acc_run
    else:
        fi = free[0]
        for i, (w, c) in enumerate(final):
            if i == fi:
                break
            variant = ((acc_run >> 8) & 3) if tag10 == 255 else (tag10 & 3)
            post_out[i] = fixed[i]
            acc_run = fixed[i]
        # output of the free entry, then remaining fixed entries
        if fi == n_after - 1:
            pre = op12['imm']
            if op11:
                pre = solve_op11(pre, op11['tag'], op11['C'] & 0xff)
                if pre is None:
                    raise RuntimeError('op11 unsat')
            if op21:
                pre = inv_sbox(pre, sbox)
            post_out[fi] = pre
            final_acc = op12['imm']
        else:
            # suffix is fully fixed, so final acc is the last fixed output
            for i in range(fi + 1, n_after):
                post_out[i] = fixed[i]
            final_acc = post_out[n_after - 1]
            post_out[fi] = 0  # overwritten if op14 needs a nibble
    if not free or free[0] != n_after - 1:
        if op21:
            final_acc = apply_sbox(final_acc, sbox)
        if op11:
            final_acc = apply_op11(final_acc, op11['tag'], op11['C'] & 0xff)
    if final_acc != op12['imm']:
        raise RuntimeError(f'stage {stage} op12 got {final_acc:#x} want {op12["imm"]:#x}')

    def nibble_of(out):
        if mode == 1:
            return (out >> 28) & 0xF
        if mode == 2:
            return out & 0xF
        return None

    Ds = []
    for i, out in enumerate(post_out):
        nb = nibble_of(out)
        Ds.append(0 if nb is None else nb)
    if op14 and mode not in (1, 2):
        need = op14['C'] & 0xff
        for i in range(n_after):
            if need <= 0:
                break
            Ds[i] = op14['tag'] & 0xff
            need -= 1
    if op14:
        want_b = op14['tag'] & 0xff
        have = sum(1 for d in Ds if d == want_b)
        if have < (op14['C'] & 0xff):
            raise RuntimeError(f'stage {stage} op14 have {have} Ds={Ds}')
    if op19 and mode in (1, 2):
        nib = op19_walk(table18, Ds)
        if ((op19['imm'] >> nib) & 1) == 0:
            raise RuntimeError(f'stage {stage} op19 nib {nib} not in mask')
    elif op19:
        fixed_d = {}
        if op14:
            tagb = op14['tag'] & 0xff
            fixed_d = {i: Ds[i] for i in range(len(Ds)) if Ds[i] == tagb}
        Ds = solve_op19_D(table18, len(Ds), op19['imm'], fixed_d)
    if op17:
        fixed = {}
        if mode in (1, 2):
            fixed = {i: Ds[i] for i in range(len(Ds))}
        elif op14:
            # keep the bytes we set to satisfy op14; forge the rest
            fixed = {i: Ds[i] for i in range(len(Ds)) if Ds[i] == (op14['tag'] & 0xff)}
        Ds = forge_crc_bytes(len(Ds), op17['imm'], fixed)
    if op24:
        modulus = lanes[op24['C'] & 7]
        base = lanes[op24['tag'] & 7] % modulus
        want = lanes[(op24['C'] >> 8) & 7]
        exp = discrete_log(base, want % modulus, modulus)
        width = 8 * n_after
        if exp.bit_length() > width:
            raise RuntimeError(f'stage {stage} op24 exp {exp:#x} does not fit in {width} bits')
        raw = exp.to_bytes(n_after, 'little')
        Ds = list(raw)
    if op25:
        if n_after != 8:
            raise RuntimeError(f'stage {stage} op25 count {n_after}')
        target = lanes[op25['tag'] & 7]
        a, b = split_u32(target)
        Ds = list(a.to_bytes(4, 'little') + b.to_bytes(4, 'little'))

    # solve imms from outputs
    imms = []
    acc_run = acc
    for i, (w, c) in enumerate(final):
        variant = ((acc_run >> 8) & 3) if tag10 == 255 else (tag10 & 3)
        imms.append(unmix(acc_run, post_out[i], w, c, i, variant, K))
        acc_run = post_out[i]

    # map imms onto pre-dedup records (xor-combine the merged pair)
    # Rebuild ordered skeleton and assign.
    raw = pack_items([(w, c, 0, 0) for w, c in pre_wc])
    ordered = [(w, c) for w, c, _, _ in unpack_items(sort_entries(raw, edx))]
    # walk dedup to know which ordered index is the survivor of each final slot
    pre_imm = [0] * len(ordered)
    pre_D = [0] * len(ordered)
    oi = 0
    for fi, (w, c) in enumerate(final):
        if oi >= len(ordered) or ordered[oi][0] != w:
            raise RuntimeError('dedup align')
        pre_imm[oi] = imms[fi]
        pre_D[oi] = Ds[fi]
        oi += 1
        # consume a merged partner if the next ordered item shares the word
        # and we still owe a merge. Partner imm 0 so xor keeps survivor imm.
        if oi < len(ordered) and ordered[oi][0] == w and (ordered[oi][1] + ordered[oi - 1][1] == c or ordered[oi][1] + ordered[oi - 1][1] > 0xffff and c == 0xffff):
            pre_imm[oi] = 0
            pre_D[oi] = 0
            oi += 1
    if oi != len(ordered):
        raise RuntimeError(f'stage {stage} unused ordered {oi}/{len(ordered)}')
    pre = [(ordered[i][0], ordered[i][1], pre_imm[i], pre_D[i]) for i in range(len(ordered))]
    got, m = dedup(pre)
    if m != merges or [g[2] for g in got] != imms or [g[3] for g in got] != Ds:
        raise RuntimeError('dedup imm check failed')
    if has_sortcheck:
        lo = (edx) & 0xffff
        hi = (edx >> 16) & 0xffff
        words = [w for w, _, _, _ in pre]
        vals = [((w * lo) & 0xffff) ^ hi for w in words]
        if any(vals[i] >= vals[i + 1] for i in range(len(vals) - 1)):
            raise RuntimeError(f'stage {stage} op4 not increasing {vals}')
    if op8 and op8['tag'] == 0:
        X = sum(c for _, c in final) & 0xffff
    elif op8:
        accs = 0
        saturated = False
        for _, c in final:
            accs += c
            if accs > 0xffff:
                saturated = True
                accs = 0xffff
                break
        X = accs
    else:
        X = 0
    H = op1['imm'] & 0xff
    ins = [slot(w & 0xff, (w >> 8) & 0xff, c, imm, D) for w, c, imm, D in pre]
    sec = section(stage, ins, X=X, H=H)
    acc_commit = acc_run
    if op21:
        acc_commit = apply_sbox(acc_commit, sbox)
    if op11:
        acc_commit = apply_op11(acc_commit, op11['tag'], op11['C'] & 0xff)
    key = commit_key(imms, [c for _, c in final], op13['imm'], acc_commit)
    return sec, key


def solve(route='route.bin', gate=0):
    recs = parse_route(route)
    prog = load_prog(recs[0])
    parts = []
    key = None
    for stage in range(1, 11):
        sec, key = build_stage(prog, stage, gate=gate)
        parts.append(sec)
        print(f'stage {stage}: section {len(sec)} bytes, next_key={key:#x}, insns={len(prog)}')
        if stage == 10:
            break
        prog = load_prog(decrypt_rec(recs[stage], key))
    data = b'FJ\n\x00' + b''.join(parts)
    return data


if __name__ == '__main__':
    data = solve()
    open('/tmp/pass.hex', 'w').write(data.hex())
    open('/tmp/pass.bin', 'wb').write(data)
    print('pass', len(data), data.hex())
