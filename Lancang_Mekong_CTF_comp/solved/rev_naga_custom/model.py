"""Python model of the `naga` simulator (reversed from disassembly of main @0xa2380).
Validated against the real binary via `naga -k KEY -l -f DECL`.
Declaration line: a(0..11) b(1..1023) c(1..255) d(1..365) e(hex<=0xffff), 6 posts x 12 lines.
"""
M64 = (1 << 64) - 1
M32 = (1 << 32) - 1


def X(s):
    s ^= (s << 13) & M64
    s ^= s >> 7
    s ^= (s << 17) & M64
    return s


def fmix(x):
    x ^= x >> 16
    x = (x * 0x7feb352d) & M32
    x ^= x >> 15
    x = (x * 0x846ca68b) & M32
    x ^= x >> 16
    return x


_crc_tab = []
for _i in range(256):
    _c = _i << 8
    for _ in range(8):
        _c = ((_c << 1) ^ 0x1021) & 0xFFFF if _c & 0x8000 else (_c << 1) & 0xFFFF
    _crc_tab.append(_c)


def crc_bytes(crc, bs):
    for byte in bs:
        crc = ((crc << 8) & 0xFFFF) ^ _crc_tab[((crc >> 8) ^ byte) & 0xFF]
    return crc


class World:
    def __init__(self, K):
        K &= 0xFFFF
        self.K = K
        x = ((K + 1) * 0xd1342543de82ef95) & M64
        x ^= 0x5f2dac21225892d7
        x = (x + 0x9e3779b97f4a7c15) & M64
        z = ((x ^ (x >> 30)) * 0xbf58476d1ce4e5b9) & M64
        z = ((z ^ (z >> 27)) * 0x94d049bb133111eb) & M64
        s = z ^ (z >> 31)
        if z == (z >> 31):
            s = 1
        self.T1 = []
        for g in range(7):
            row = []
            for i in range(12):
                s = X(s)
                row.append(s % 58 + 3)
            self.T1.append(row)
        s = X(s); A = s & 0x1FFFF; self.L1 = A + 0x20000
        s = X(s); B = s & 0x1FFFF; self.L2 = A + B + 0x40000
        s = X(s); self.V98 = s % 7
        s = X(s); self.V80 = s % 29
        s = X(s); self.SH = s % 3 + 3
        self.U = []
        for k in range(6):
            s = X(s); self.U.append(s % 61 + 70)
        s = X(s); self.Q = s & 0xFFFF
        self.P = []
        for k in range(6):
            s = X(s); self.P.append(s % 1001 + 400)
        s1 = X(s)
        s2 = X(s1)
        self.CRC0 = s1 & 0xFFFF
        self.H0 = s2 & M32
        s = s2
        self.W = []
        for k in range(6):
            s = X(s); self.W.append(s % 3 + 2)
        s = X(s)
        self.AD0 = s % 65521


class State:
    """Mutable simulation state (copyable) for incremental search."""
    __slots__ = ("H", "CRC", "AD", "T", "LV", "FE", "FI", "HW", "M", "CRY", "CV")

    def copy(self):
        n = State.__new__(State)
        n.H = self.H; n.CRC = self.CRC; n.AD = self.AD
        n.T = self.T[:]; n.LV = self.LV; n.FE = self.FE; n.FI = self.FI
        n.HW = self.HW; n.M = self.M[:]; n.CRY = self.CRY; n.CV = self.CV
        return n


def init_state(w):
    s = State()
    s.H = w.H0; s.CRC = w.CRC0; s.AD = w.AD0
    s.T = [0] * 6; s.LV = 0; s.FE = 0; s.FI = 0; s.HW = 0
    s.M = w.P[:]; s.CRY = 0; s.CV = 0
    return s


def line_text(a, b, c, d, e):
    return "%02d %04d %03d %03d %04x\n" % (a, b, c, d, e)


def step(w, st, post, a, b, c, d, e):
    """Process one (sorted) entry in place."""
    edx = (e * 0x9e3779b1) & M32
    edx ^= (w.H0 ^ st.H)
    edx ^= (a * 0x85ebca6b) & M32
    edx ^= (d * 0xc2b2ae35) & M32
    g = fmix(edx) % 7
    BC = b * c
    st.CV += BC
    if w.L1 >= st.CV:
        tm = 100
    elif w.L2 >= st.CV:
        tm = 112
    else:
        tm = 130
    V = w.T1[g][a] * BC
    t = tm * V
    q1 = t // 10000
    r = t - q1 * 10000 + st.CRY
    q2 = r // 10000
    st.CRY = r - q2 * 10000
    lev = q1 + q2
    z = (((37 * d + w.V80) & M32) * 0x4f72c235 + 0x469ee58) & M32
    if z <= 0x8d3dcb0:
        lev += (lev * 15) // 100
    if e & 1:
        if (d + w.V98) % 7 >= 5:
            lev //= 2
    HW = st.HW
    if V <= 2 * HW:
        r8 = lev
        r11 = 0
    else:
        r8 = lev + (V - HW) // 32
        r11 = (V - HW) // 8
    st.HW = max(V, HW - (HW >> w.SH))
    idx = a >> 1
    mm = st.M[idx] - b
    if mm >= 0:
        r14 = 0
        st.M[idx] = mm
    else:
        r14 = -3 * mm
        r8 += r14 >> 3
        st.M[idx] = 0
    u = ((b >> 4) + 250) * w.U[post]
    st.T[idx] += u // 800 + r8
    st.FE += u // 100
    st.LV += r11
    st.FI += r14
    hh = ((a << 24) | (b << 8) | g) ^ st.H ^ (lev & M32)
    st.H = fmix(hh & M32)
    st.CRC = crc_bytes(st.CRC, line_text(a, b, c, d, e).encode())
    st.AD = (st.AD * 61 + ((c + b + d + e) & 15)) % 65521


def record(st):
    return st.T[:] + [st.LV, st.FE, st.FI, st.HW, st.CRC, st.H, st.AD]


def end_post(w, st):
    Tc = st.T[:]
    for k in range(6):
        st.T[k] += Tc[(k + 5) % 6] >> w.W[k]
    for k in range(6):
        st.M[k] = st.M[k] // 2 + w.P[k]


def prepare_post(w, lines):
    """lines: list of 12 (a,b,c,d,e). Returns (sorted kept entries, dups)."""
    seen = []
    kept = []
    dups = 0
    for ln in lines:
        if ln[4] in seen:
            dups += 1
        else:
            kept.append(ln)
        seen.append(ln[4])
    kept.sort(key=lambda t: (t[3] << 16) | (w.Q ^ t[4]))
    return kept, dups


def simulate(K, decl):
    """decl: list of 72 tuples. Returns (records dict {(post,k): rec}, final_record, w)."""
    w = World(K)
    st = init_state(w)
    recs = {}
    for p in range(6):
        kept, dups = prepare_post(w, decl[p * 12:(p + 1) * 12])
        st.FI += dups * 7500
        st.CV = 0
        for j, (a, b, c, d, e) in enumerate(kept):
            step(w, st, p, a, b, c, d, e)
            recs[(p, j + 1)] = record(st)
        end_post(w, st)
        recs[(p, 0)] = record(st)
    return recs, record(st), w


def fingerprint(rec):
    h = 0x811c9dc5
    for q in rec:
        for i in range(8):
            h ^= (q >> (8 * i)) & 0xFF
            h = (h * 0x1000193) & M32
    h ^= h >> 16
    h = (h * 0x7feb352d) & M32
    h ^= h >> 15
    h = (h * 0x846ca68b) & M32
    return h >> 20


def parse_decl(text):
    out = []
    for ln in text.strip().split("\n"):
        f = ln.split()
        out.append((int(f[0]), int(f[1]), int(f[2]), int(f[3]), int(f[4], 16)))
    return out


if __name__ == "__main__":
    import sys
    d = parse_decl(open(sys.argv[1]).read())
    recs, fin, w = simulate(int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x5ea5, d)
    print("fingerprint %03x" % fingerprint(fin))
    names = ["TREASURY-%d" % i for i in range(6)] + ["LEVY", "FEES", "FINES", "HIGH-WATER", "SEAL", "AUDIT", "STAMP"]
    for i, n in enumerate(names):
        print("%-12s%s" % (n, ("%x" if n in ("SEAL", "AUDIT") else "%d") % fin[i]))
