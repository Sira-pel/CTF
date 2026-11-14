"""Live client for the Naga Customs desk (official host only, one connection).
Flow: PLAIN -> ASSIGN -> PROBE (identify 16-bit key) -> solve locally -> SUBMIT.
"""
import socket, sys, re, time, pickle
sys.path.insert(0, '/home/sira/Documents/CTF/Lancang_Mekong_CTF_comp/solved/rev_naga_custom')
from solver import *
from fptab import DECLS

HOST, PORT = "47.131.225.172", 31906
SCR = '/tmp/claude-1000/-home-sira--claude-spares-spare-GKF30R/82842250-d20e-492b-9228-fe3a89eef61c/scratchpad'
FP = pickle.load(open(SCR + '/fptab.pkl', 'rb'))
DO_SUBMIT = "--submit" in sys.argv

s = socket.create_connection((HOST, PORT), timeout=10)
buf = b""


def recv_until(pred, timeout=8):
    global buf
    end = time.time() + timeout
    while time.time() < end:
        txt = re.sub(rb'\x1b\[[0-9;]*[A-Za-z]|\x1b[78]', b'\n', buf).decode('latin1')
        if pred(txt):
            return txt
        s.settimeout(0.5)
        try:
            d = s.recv(65536)
            if not d:
                break
            buf += d
        except socket.timeout:
            pass
    return re.sub(rb'\x1b\[[0-9;]*[A-Za-z]|\x1b[78]', b'\n', buf).decode('latin1')


def cmd(line, pred, timeout=8):
    global buf
    buf = b""
    s.sendall(line.encode() + b"\n")
    return recv_until(pred, timeout)


time.sleep(1.0)
s.sendall(b"PLAIN\n")
t = recv_until(lambda t: "READY" in t, 6)
print("PLAIN ->", "READY" in t)
t = cmd("ASSIGN", lambda t: "PROBES" in t)
tg = parse_targets(t)
print("targets:", len(tg))
assert len(tg) == 12, t

cands = None
for name in "ABC":
    d = DECLS[name]
    text = ";".join(line_text(*x).rstrip() for x in d)
    t = cmd("PROBE " + text, lambda t: re.search(r"FP [0-9a-f]{3}", t) is not None)
    m = re.search(r"FP ([0-9a-f]{3})", t)
    if not m:
        print("probe failed:", t[-300:]); sys.exit(1)
    fp = int(m.group(1), 16)
    idx = "ABC".index(name)
    c = {k for k in range(65536) if FP[k][idx] == fp}
    cands = c if cands is None else cands & c
    print("probe", name, "fp", m.group(1), "candidates:", len(cands))
    if len(cands) <= 1:
        break
print("candidate keys:", sorted(cands)[:10])
if not cands:
    sys.exit(2)

if not DO_SUBMIT:
    sys.exit(0)

for K in sorted(cands)[:3]:
    decl = solve(K, tg, seed=5)
    text = ";".join(line_text(*x).rstrip() for x in decl)
    t = cmd("SUBMIT " + text, lambda t: "\n" in t.strip() and len(t.strip()) > 0 and ("ERROR" in t or "FLAG" in t.upper() or "OPEN" in t or "SEALED" in t or "TRIES" in t.upper() or "LEFT" in t.upper()), 10)
    print("SUBMIT key %04x ->" % K)
    print(re.sub(r'\n+', '\n', t).strip()[-600:])
    if "OPEN" in t or "flag" in t.lower() or "{" in t:
        break
s.sendall(b"QUIT\n")
