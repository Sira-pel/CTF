import sys
out=[int(x) for x in open(sys.argv[1]).read().split()]
n=len(out); assert n==264
def perm(seed,L=30):
    used=[False]*L; slots=[]
    for i in range(L):
        y=(i*seed)%L
        while used[y]: y=(y+1)%L
        used[y]=True; slots.append(y)
    return slots   # bit i of raw -> slot slots[i]
cols=[]
prev=0
for j in range(n):
    i=j+1
    seed=(i*127)%500
    rnd=(((i*327)%681)+344)%313
    fun=out[j]^prev^rnd
    prev=out[j]
    s=format(fun,'060b')
    s=s.zfill(60)
    pairs=[s[2*k:2*k+2] for k in range(30)]
    sl=perm(seed)
    raw=''.join('1' if pairs[sl[k]]=='11' else '0' for k in range(30))
    assert all(p in('11','00') for p in pairs),(j,pairs)
    cols.append(raw)
rows=[''.join(c[r*6:(r+1)*6] for c in cols) for r in range(5)]
for r in rows: print(r)
print()
# render: each col of 6 bits per row -> treat as glyph grid
for r in rows: print(r.replace('1','#').replace('0',' '))
