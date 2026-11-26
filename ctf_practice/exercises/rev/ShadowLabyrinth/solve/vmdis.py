import struct,sys,collections
c=open(sys.argv[1],'rb').read(); M=list(struct.unpack('<%dI'%(len(c)//4),c))
N={0:1,1:1,2:2,3:2,4:2,5:2,6:2,7:2,8:2,9:2,10:1,11:1,12:1,13:0,14:1,15:0}
nm=['clr','one','addi','subi','shli','add','sub','xor','st','ld','jz','jnz','jmp','in','print','exit']
ip=0; out=[]; cnt=collections.Counter()
while ip<len(M):
    op=M[ip]
    if op>15: out.append(f'{ip:6x}: DATA {op:#x}'); ip+=1; continue
    a=M[ip+1:ip+1+N[op]]; cnt[op]+=1
    s=f'{ip:6x}: {nm[op]} {a}'
    if op in (10,11,12): s+=f' -> {ip+1+a[0]-1:#x}' 
    if op in (8,9): s+=f' [{ip+3+a[1]:#x}]'
    if op==14:
        p=ip+2+a[0]; t=''
        while M[p]: t+=chr(M[p]&0xff); p+=1
        s+=' '+repr(t)
    out.append(s); ip+=1+N[op]
    if op==15: pass
open(sys.argv[2],'w').write('\n'.join(out)); print(cnt)
