import re, bisect

lines = open("/tmp/claude-1000/-home-sira--claude-spares-spare-J6RNHV/c452b978-a9ed-42df-a662-41eda420768f/scratchpad/vuln_disasm.txt").read().splitlines()
re_addr = re.compile(r'^\s*([0-9a-f]+):\s+[0-9a-f ]+\t(.*)$')
insns = []
for l in lines:
    m = re_addr.match(l)
    if m:
        addr = int(m.group(1),16)
        text = m.group(2).split('#')[0].split(';')[0].strip()
        insns.append((addr, text))

addrs_list = [a for a,_ in insns]
addr_to_idx = {a:i for i,(a,t) in enumerate(insns)}

def func_start(addr):
    idx = addr_to_idx.get(addr)
    if idx is None:
        idx = bisect.bisect_right(addrs_list, addr) - 1
    while idx > 0:
        a,t = insns[idx]
        if t == 'push   ebp' and idx+1 < len(insns) and insns[idx+1][1]=='mov    ebp,esp':
            return a
        idx -= 1
    return None

# build caller map once: for every call instruction, record (call_addr, target_addr)
calls = []
for a,t in insns:
    if t.startswith('call'):
        m = re.search(r'call\s+([0-9a-f]+)', t)
        if m:
            calls.append((a, int(m.group(1),16)))

from collections import defaultdict
callers_of = defaultdict(list)
for a,tgt in calls:
    callers_of[tgt].append(a)

MAIN = 0x0814cde2
target = 0x0808ba1f

# BFS upward, but at each step choose only callers; annotate with total caller count of each candidate enclosing func (computed lazily)
visited = set([target])
frontier = [(target,[])]
depth=0
path_found=None
while frontier and depth<40:
    depth+=1
    nf = []
    for f,path in frontier:
        if f == MAIN:
            path_found = path
            break
        for c in callers_of.get(f, []):
            fs = func_start(c)
            if fs is None: continue
            newpath = path+[(f,c,fs)]
            if fs == MAIN:
                path_found = newpath
                break
            if fs not in visited:
                visited.add(fs)
                nf.append((fs,newpath))
        if path_found: break
    if path_found: break
    frontier = nf
    print(f"depth {depth}: frontier size {len(frontier)}")

if path_found:
    print("PATH FOUND, length", len(path_found))
    for f,c,fs in path_found:
        print(f"  func {hex(f)} called from {hex(c)} inside {hex(fs)} (callers of fs: {len(callers_of.get(fs,[]))})")
else:
    print("no path found within depth limit; visited", len(visited))
