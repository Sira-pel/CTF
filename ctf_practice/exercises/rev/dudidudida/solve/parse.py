import re, sys, json, struct
lines=open(sys.argv[1]).read().splitlines()
f=open(sys.argv[2],'rb').read()
def rd(va,n): o=va-0x1400d9000+0xd7c00; return f[o:o+n]
ins=[]
for l in lines:
    m=re.match(r'([0-9a-f]+):\t(\S+)\s*(.*)',l)
    if m: ins.append((int(m.group(1),16),m.group(2),m.group(3)))
def cm(s):
    m=re.search(r'# (0x[0-9a-f]+)',s); return int(m.group(1),16) if m else None
cells={}
# find cell starts: push rbp; mov rbp,rsp; sub; push*3; mov;mov; cmp DWORD PTR [rip..],0xffffffff
starts=[]
for i,(a,mn,op) in enumerate(ins):
    if mn=='cmp' and ',0xffffffff' in op and 'rip' in op and 'DWORD' in op:
        # walk back to push rbp
        j=i
        while ins[j][1]!='push' or ins[j][2]!='rbp': j-=1
        starts.append((j,i))
starts.sort()
for n,(j,i) in enumerate(starts):
    end=starts[n+1][0] if n+1<len(starts) else min(len(ins),j+3000)
    body=ins[j:end]
    fa=body[0][0]
    idx=(cm(ins[i][2])-0x1400d9aa0)//4
    c={'idx':idx,'val':None,'map':{},'edges':{},'check':None}
    lastecx=lastedx=None; lastr8=None; curdir=None; lastrdx=None
    for k,(a,mn,op) in enumerate(body):
        if mn=='mov' and op.startswith('BYTE PTR [rax],0x') and c['val'] is None: c['val']=int(op.split(',')[1],16)
        if mn=='xor' and op=='ecx,ecx': lastecx=0
        if mn=='mov' and op.startswith('ecx,0x'): lastecx=int(op[4:],16)
        if mn=='xor' and op=='edx,edx': lastedx=0
        if mn=='mov' and op.startswith('edx,0x'): lastedx=int(op[4:],16)
        if mn=='lea' and op.startswith('r8,'): lastr8=cm(op)
        if mn=='lea' and op.startswith('rdx,'): lastrdx=cm(op)
        if mn=='lea' and op.startswith('rcx,'):
            t=cm(op)
            if t and 0x1400da300<=t<0x1400dabc0: c['check']=t
        if mn=='call':
            t=int(op,16)
            if t==0x1400424e0: pend=lastedx
            if t==0x14004aee0: curdir=lastecx
            if t==0x14004afa0 and curdir is not None: c['edges'][curdir]=lastr8; curdir=None
            if t==0x140048a10 and curdir is not None: c['edges'][curdir]='FAIL'; curdir=None
        if mn=='mov' and op=='QWORD PTR [rax+0x8],rdx' and lastrdx:
            c['map'][pend]=rd(lastrdx,2).decode()
        if mn=='ret' and len(c['edges'])==4: break
    cells[fa]=c
print(len(cells))
# checkpoint constants: read decimal string at address, length is in 'mov bl,0x4d' - just read until NUL
for a,c in cells.items():
    if c['check']:
        o=c['check']-0x1400d9000+0xd7c00; c['checkval']=int(f[o:f.index(b'\0',o)].decode())
json.dump({hex(a):c for a,c in cells.items()},open(sys.argv[3],'w'),indent=0,default=str)
from collections import Counter
print(Counter(len(c['edges']) for c in cells.values()), sum(1 for c in cells.values() if c['check']), sum(1 for c in cells.values() if c['map']))
print(sorted(Counter(c['idx'] for c in cells.values()).values())[-3:], min(c['idx'] for c in cells.values()),max(c['idx'] for c in cells.values()))
for a,c in list(cells.items())[:3]: print(hex(a),c)
