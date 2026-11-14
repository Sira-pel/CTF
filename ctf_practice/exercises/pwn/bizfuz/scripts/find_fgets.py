import re, sys
from collections import Counter

lines = open("/tmp/claude-1000/-home-sira--claude-spares-spare-J6RNHV/c452b978-a9ed-42df-a662-41eda420768f/scratchpad/vuln_disasm.txt").read().splitlines()

re_addr = re.compile(r'^\s*([0-9a-f]+):\s+[0-9a-f ]+\t(.*)$')
re_lea_ebp_minus = re.compile(r'^lea\s+e[a-z]{2},\[ebp-0x([0-9a-f]+)\]$')
re_push_imm = re.compile(r'^push\s+0x([0-9a-f]+)$')
re_call_fgets = re.compile(r'^call\s+[0-9a-f]+\s*<fgets@plt>')

insns = []
for l in lines:
    m = re_addr.match(l)
    if m:
        addr = int(m.group(1),16)
        text = m.group(2).split('#')[0].split(';')[0].strip()
        insns.append((addr, text))

results = []
last_ebp_off = None
last_push_imm = None
pushes_recent = []  # (addr, kind, value)

for i,(addr,text) in enumerate(insns):
    mlea = re_lea_ebp_minus.match(text)
    mpushimm = re_push_imm.match(text)
    if mlea:
        pushes_recent.append(('ebp', int(mlea.group(1),16)))
    if mpushimm:
        pushes_recent.append(('imm', int(mpushimm.group(1),16)))
    if re_call_fgets.match(text):
        # find nearest ebp offset and nearest imm before this call (within last 8 entries)
        buf_off = None
        size = None
        for kind, val in reversed(pushes_recent[-8:]):
            if kind=='ebp' and buf_off is None:
                buf_off = val
            if kind=='imm' and size is None:
                size = val
        results.append((addr, buf_off, size))
    # trim history occasionally
    if len(pushes_recent) > 20:
        pushes_recent = pushes_recent[-10:]

print("total fgets:", len(results))
summary = Counter()
for addr, buf_off, size in results:
    summary[(buf_off, size)] += 1

print("\n=== (buf_off, size) -> count, sorted by overflow margin ===")
rows = []
for (buf_off, size), cnt in summary.items():
    if buf_off is None or size is None:
        margin = None
    else:
        margin = size - buf_off   # positive means size reaches/exceeds distance to saved ebp -> overwrite ebp/ret
    rows.append((margin, buf_off, size, cnt))

rows.sort(key=lambda r: (r[0] is None, -(r[0] or -999)))
for margin, buf_off, size, cnt in rows:
    print(f"buf_off={hex(buf_off) if buf_off else buf_off} size={hex(size) if size else size} margin={margin} count={cnt}")
