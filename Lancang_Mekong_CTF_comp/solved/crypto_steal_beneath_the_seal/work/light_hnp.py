"""Cheap HNP test: LLL on a few noisy samples, then check every sample."""
import json
from pathlib import Path

import gmpy2

gmpy2.get_context().precision = 1200

DATA = json.loads(
    Path("/home/sira/Documents/CTF/Lancang_Mekong_CTF_comp/solved/crypto_steal_beneath_the_seal/instance.json").read_text()
)
M = int(DATA["modulus"])
ANCHOR = int(DATA["anchor"])
BND = int(DATA["error_bound"])
HMAX = 1 << int(DATA["hidden_offset_bits"])
SAMPLES = [(int(s["a"]), int(s["b"])) for s in DATA["samples"]]


def lll(basis, delta=gmpy2.mpfr("0.75"), max_iter=5000):
    B = [row[:] for row in basis]
    n = len(B)
    m = len(B[0])
    k = 1
    it = 0
    while k < n and it < max_iter:
        it += 1
        mu, nrm = gram(B)
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > gmpy2.mpfr("0.5"):
                q = int(gmpy2.rint(mu[k][j]))
                if q:
                    for t in range(m):
                        B[k][t] -= q * B[j][t]
                    mu, nrm = gram(B)
        if nrm[k] >= (delta - mu[k][k - 1] ** 2) * nrm[k - 1]:
            k += 1
        else:
            B[k], B[k - 1] = B[k - 1], B[k]
            k = max(k - 1, 1)
    if it >= max_iter:
        print("LLL hit iteration cap", it)
    else:
        print("LLL iterations", it)
    return B


def gram(B):
    n = len(B)
    m = len(B[0])
    mu = [[gmpy2.mpfr(0) for _ in range(n)] for _ in range(n)]
    nrm = [gmpy2.mpfr(0) for _ in range(n)]
    bstar = []
    for i in range(n):
        v = [gmpy2.mpfr(x) for x in B[i]]
        for j in range(i):
            # mu_ij = <b_i, b*_j> / ||b*_j||^2
            dot = gmpy2.mpfr(0)
            for t in range(m):
                dot += gmpy2.mpfr(B[i][t]) * bstar[j][t]
            mu[i][j] = dot / nrm[j]
            coef = mu[i][j]
            for t in range(m):
                v[t] -= coef * bstar[j][t]
        bstar.append(v)
        acc = gmpy2.mpfr(0)
        for t in range(m):
            acc += v[t] * v[t]
        nrm[i] = acc
    return mu, nrm


def centered(x):
    x %= M
    if x > M // 2:
        x -= M
    return x


def check_h(h):
    errs = []
    ok = True
    for a, b in SAMPLES:
        e = centered(b - a * (ANCHOR + h))
        errs.append(e)
        if abs(e) >= BND:
            ok = False
    return ok, errs


def attack(n_use):
    pairs = SAMPLES[:n_use]
    cs = [((b - a * ANCHOR) % M) for a, b in pairs]
    # Balanced Kannan embedding:
    # short vector ~= (S*e_i, h*BND, -S*BND) with S = HMAX
    S = HMAX
    rows = []
    for i in range(n_use):
        row = [0] * (n_use + 2)
        row[i] = M * S
        rows.append(row)
    row_a = [a * S for a, _ in pairs] + [BND, 0]
    row_c = [c * S for c in cs] + [0, S * BND]
    rows.append(row_a)
    rows.append(row_c)
    print("reducing", len(rows), "x", len(rows[0]), "n_use", n_use)
    R = lll(rows)
    T = S * BND
    hits = []
    for row in R:
        emb = row[-1]
        if emb == 0 or T == 0 or abs(emb) % T != 0:
            continue
        mult = emb // -T  # row = mult * (S*e, h*BND, -T) if we subtracted target once... 
        # Our generator uses integer combinations. If mult copies of target were used:
        # coef_c * row_c + coef_a * row_a + ...
        # emb = coef_c * T
        coef_c = emb // T
        if coef_c == 0:
            continue
        # secret coord = coef_a * BND, and we want coef_a / coef_c = h? 
        # vector = coef_a * row_a + coef_c * row_c + sum k_i row_i
        # secret coord = coef_a * BND
        # error_i * S = coef_a * a_i * S + coef_c * c_i * S + k_i * M * S
        # If coef_c == -1 and coef_a == h: error = h*a - c + k M
        sec = row[-2]
        if sec % BND != 0:
            continue
        coef_a = sec // BND
        # normalize so coef_c = -1 => h = coef_a
        if coef_c < 0:
            h = coef_a // -coef_c if coef_a % -coef_c == 0 else None
        else:
            h = None
        if h is None:
            # try direct: the ratio
            if coef_a % coef_c == 0:
                # vector = coef_c * (h' * row_a - row_c + ...) if coef_a = coef_c * h' and coef_c negative? 
                h_try = -(coef_a // coef_c)
            else:
                h_try = None
        else:
            h_try = h
        if h_try is None:
            continue
        if not (0 <= h_try < HMAX):
            # also allow the negative embedding interpretation already handled
            continue
        ok, errs = check_h(h_try)
        print("candidate", h_try, "ok", ok, "maxerr", max(abs(e) for e in errs))
        hits.append((h_try, ok))
    # also dump smallest vectors' tail for debugging
    print("--- tails ---")
    for row in R[:8]:
        print(row[-2], row[-1], "sqbits", sum(x * x for x in row).bit_length())
    return hits


if __name__ == "__main__":
    # unit: LLL on a tiny known basis
    U = lll([[1, 1, 1], [-1, 0, 2], [3, 5, 6]])
    print("unit basis", U)
    attack(8)
