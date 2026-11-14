"""Constructive solver for the Naga Customs ledger (see model.py).

Given key K and target lines (post, snap, [(reg,mask,val)...]) build a 72-line declaration whose
snapshots (after 6th sorted entry = snap 6, and end-of-post = snap 0) satisfy all masked targets.

Pattern per post (observed): snap 6 -> two T regs + one of {9 HW, 10 CRC, 12 Adler}; snap 0 -> three T regs.
Entries are given increasing days so sorted order == creation order.
"""
import random
from model import *

rnd = random.Random(1)


def contrib(w, st, post, a, b, c, d, e):
    """Non-mutating: returns (idx, T-add, newHW) for an entry."""
    edx = (e * 0x9e3779b1) & M32
    edx ^= (w.H0 ^ st.H)
    edx ^= (a * 0x85ebca6b) & M32
    edx ^= (d * 0xc2b2ae35) & M32
    g = fmix(edx) % 7
    BC = b * c
    cv = st.CV + BC
    tm = 100 if w.L1 >= cv else (112 if w.L2 >= cv else 130)
    V = w.T1[g][a] * BC
    t = tm * V
    q1 = t // 10000
    r = t - q1 * 10000 + st.CRY
    lev = q1 + r // 10000
    z = (((37 * d + w.V80) & M32) * 0x4f72c235 + 0x469ee58) & M32
    if z <= 0x8d3dcb0:
        lev += (lev * 15) // 100
    if (e & 1) and (d + w.V98) % 7 >= 5:
        lev //= 2
    HW = st.HW
    r8 = lev if V <= 2 * HW else lev + (V - HW) // 32
    newhw = max(V, HW - (HW >> w.SH))
    idx = a >> 1
    mm = st.M[idx] - b
    if mm < 0:
        r8 += (-3 * mm) >> 3
    u = ((b >> 4) + 250) * w.U[post]
    nh = fmix((((a << 24) | (b << 8) | g) ^ st.H ^ (lev & M32)) & M32)
    return idx, u // 800 + r8, newhw, nh


class Fail(Exception):
    pass


def solve(K, targets, seed=1, verbose=False):
    rr = random.Random(seed)
    w = World(K)
    st = init_state(w)
    decl = []

    for p in range(6):
        t6 = targets[(p, 6)]
        t0 = targets[(p, 0)]
        T6 = [(r, m, v) for (r, m, v) in t6 if r <= 5]
        X6 = [(r, m, v) for (r, m, v) in t6 if r > 5]
        T0 = [(r, m, v) for (r, m, v) in t0 if r <= 5]
        assert all(r > 5 for (r, m, v) in t0 if r > 5) and not [x for x in t0 if x[0] > 5], "unsupported snap0 regs"
        assert len(X6) <= 1, "unsupported snap6 pattern"
        st.CV = 0
        used_e = set()
        days = [20 + 25 * j for j in range(12)]
        entries = []

        def fresh_e():
            while True:
                e = rr.randrange(65536)
                if e not in used_e:
                    return e

        def apply(a, b, c, d, e):
            used_e.add(e)
            step(w, st, p, a, b, c, d, e)
            entries.append((a, b, c, d, e))

        def adjust_T(k, m, v, d, tries=3000000):
            """find entry adding to T[k] s.t. (T[k]+add)&m == v."""
            for _ in range(tries):
                a = 2 * k + rr.randrange(2)
                b = rr.randrange(1, 1024)
                c = rr.randrange(1, 256)
                e = fresh_e()
                idx, add, _hw, _h = contrib(w, st, p, a, b, c, d, e)
                if ((st.T[k] + add) & m) == v:
                    apply(a, b, c, d, e)
                    return
            raise Fail("adjust_T")

        def filler(d, allowed_cargo=None, s=None):
            cs = allowed_cargo if allowed_cargo is not None else list(range(12))
            a = rr.choice(cs)
            b = rr.randrange(1, 1024)
            c = rr.randrange(1, 256)
            e = fresh_e()
            if s is not None:
                e = (e & ~15) | ((s - b - c - d) & 15)
                while e in used_e:
                    e = (fresh_e() & ~15) | ((s - b - c - d) & 15)
            apply(a, b, c, d, e)

        Tk6 = [r for (r, m, v) in T6]
        free_cargo = [a for a in range(12) if (a >> 1) not in Tk6]
        snap = st.copy()
        # ---- phase A: entries 0..5 ----
        for attempt in range(60):
            used_e.clear(); entries.clear()
            st.H = snap.H; st.CRC = snap.CRC; st.AD = snap.AD; st.T = snap.T[:]
            st.LV = snap.LV; st.FE = snap.FE; st.FI = snap.FI; st.HW = snap.HW
            st.M = snap.M[:]; st.CRY = snap.CRY; st.CV = 0
            j = 0
            for (r, m, v) in T6:
                adjust_T(r, m, v, days[j]); j += 1
            if not X6:
                while j < 6:
                    filler(days[j], free_cargo); j += 1
                break
            r, m, v = X6[0]
            if r == 12:  # Adler: fillers j..5 choose s values
                nf = 6 - j
                A = st.AD
                # table of sums
                target = v
                sol = None
                # enumerate s-vectors for nf fillers
                import itertools
                pw = [pow(61, nf - 1 - i, 65521) for i in range(nf)]
                # A_final = 61^nf * A + sum pw[i]*(s_i) with s_i in 0..15 (inner ordering)
                base = (pow(61, nf, 65521) * A) % 65521
                need = (target - base) % 65521
                # meet in the middle
                h = nf // 2
                left = {}
                for sv in itertools.product(range(16), repeat=h):
                    left.setdefault(sum(pw[i] * sv[i] for i in range(h)) % 65521, sv)
                cand = None
                for sv in itertools.product(range(16), repeat=nf - h):
                    x = (need - sum(pw[h + i] * sv[i] for i in range(nf - h))) % 65521
                    if x in left:
                        cand = left[x] + sv
                        break
                if cand is None:
                    continue
                for i in range(nf):
                    filler(days[j], free_cargo, s=cand[i]); j += 1
                assert st.AD == target, (st.AD, target)
                break
            elif r == 10:  # CRC: fillers then last entry scan e
                while j < 5:
                    filler(days[j], free_cargo); j += 1
                found = False
                for _ in range(40):
                    a = rr.choice(free_cargo)
                    b = rr.randrange(1, 1024)
                    c = rr.randrange(1, 256)
                    d = days[5]
                    pre = "%02d %04d %03d %03d " % (a, b, c, d)
                    crc0 = crc_bytes(st.CRC, pre.encode())
                    for e in range(65536):
                        if e in used_e:
                            continue
                        if crc_bytes(crc0, ("%04x\n" % e).encode()) == v:
                            apply(a, b, c, d, e)
                            found = True
                            break
                    if found:
                        break
                if found:
                    break
                continue
            elif r == 9:  # HW
                while j < 5:
                    filler(days[j], free_cargo); j += 1
                ok = False
                for _ in range(3000000):
                    a = rr.choice(free_cargo)
                    b = rr.randrange(1, 1024)
                    c = rr.randrange(1, 256)
                    e = fresh_e()
                    idx, add, nh, _h = contrib(w, st, p, a, b, c, days[5], e)
                    if (nh & m) == v and nh > st.HW - (st.HW >> w.SH):
                        apply(a, b, c, days[5], e)
                        ok = True
                        break
                if ok:
                    break
                continue
            elif r == 11:  # AUDIT hash chain
                while j < 5:
                    filler(days[j], free_cargo); j += 1
                ok = False
                for _ in range(3000000):
                    a = rr.choice(free_cargo)
                    b = rr.randrange(1, 1024)
                    c = rr.randrange(1, 256)
                    e = fresh_e()
                    idx, add, nh, nH = contrib(w, st, p, a, b, c, days[5], e)
                    if (nH & m) == v:
                        apply(a, b, c, days[5], e)
                        ok = True
                        break
                if ok:
                    break
                continue
            else:
                raise Fail("unsupported reg %d" % r)
        else:
            raise Fail("phase A post %d" % p)
        rec6 = record(st)
        for (r, m, v) in t6:
            assert rec6[r] & m == v, ("snap6", p, r, rec6[r] & m, v)
        # ---- phase B: entries 6..11 ----
        C = [r for (r, m, v) in T0]
        Cset = set(C)
        # order adjusters so that k-1's adjuster precedes k's
        order = sorted(C, key=lambda k: (k - 1) % 6 in Cset)
        j = 6
        nadj = len(order)
        while j < 12 - nadj:
            filler(days[j]); j += 1
        # adjusters; need transfer-aware targets
        Tprev = None
        for k in order:
            m, v = [(mm, vv) for (r, mm, vv) in T0 if r == k][0]
            # T_final[k] = T[k] + (Tc[(k-1)%6] >> W[k]); Tc = T before transfer.  Tc[k-1] final iff k-1 not adjusted later.
            # (k-1 adjusters come earlier in `order`, so Tc[k-1] is already final)
            pre = st.T[(k - 1) % 6] >> w.W[k]
            # search with target on T[k]+pre
            d = days[j]
            found = False
            for _ in range(3000000):
                a = 2 * k + rr.randrange(2)
                b = rr.randrange(1, 1024)
                c = rr.randrange(1, 256)
                e = fresh_e()
                idx, add, _hw, _h = contrib(w, st, p, a, b, c, d, e)
                if ((st.T[k] + add + pre) & m) == v:
                    apply(a, b, c, d, e)
                    found = True
                    break
            if not found:
                raise Fail("phase B")
            j += 1
        assert j == 12
        end_post(w, st)
        rec0 = record(st)
        for (r, m, v) in t0:
            assert rec0[r] & m == v, ("snap0", p, r, rec0[r] & m, v)
        decl.extend(entries)
        if verbose:
            print("post", p, "ok")
    return decl


def parse_targets(text):
    tg = {}
    for ln in text.strip().split("\n"):
        f = ln.split()
        if len(f) < 3 or not f[0].isdigit():
            continue
        p, k, n = int(f[0]), int(f[1]), int(f[2])
        lst = []
        for i in range(n):
            r = int(f[3 + 3 * i]); m = int(f[4 + 3 * i], 16); v = int(f[5 + 3 * i], 16)
            lst.append((r, m, v))
        tg[(p, k)] = lst
    return tg


def decl_text(decl):
    return "\n".join(line_text(*x).rstrip() for x in decl) + "\n"
