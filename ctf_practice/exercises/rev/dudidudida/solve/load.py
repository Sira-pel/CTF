import json, hashlib, sys
sys.setrecursionlimit(10000)
c = json.load(open(sys.argv[1])); exe = open(sys.argv[2], 'rb').read()
o = 0x1400d9e40 - 0x1400d9000 + 0xd7c00
M = int.from_bytes(exe[o:o+32], 'little')
addrs = sorted(int(a, 16) for a in c)
win = max(a for a in addrs if a < 0x140005de9); WINC = c[hex(win)]['idx']
cells = {}
for a, x in c.items():
    e = {int(d): (t if t == 'FAIL' else c[hex(int(t))]['idx']) for d, t in x['edges'].items()}
    cells[x['idx']] = dict(e={d: t for d, t in e.items() if t != 'FAIL'},
                           map={int(k): v for k, v in x['map'].items()}, cv=x.get('checkval'))
cells[WINC]['e'][2] = 'WIN'
H = {i: int(hashlib.sha256(bytes([i])).hexdigest(), 16) for i in range(224)}
START = c['0x14000b180']['idx']; N = 224
PREFIX = b'HTB{'
visited = [False] * N; path = []; bits = []
