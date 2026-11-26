import struct,sys,random
c=open(__file__.rsplit('/',1)[0]+'/code.bin','rb').read(); CODE=list(struct.unpack('<%dI'%(len(c)//4),c))
MK=0xffffffff
def run(inp):
    M=CODE[:]+[0]*0x100; R=[0]*64; zf=0; ip=0; k=0; out=''
    while True:
        op=M[ip]; ip+=1
        if op==0: R[M[ip]]=0; ip+=1
        elif op==1: R[M[ip]]=1; ip+=1
        elif op==2: R[M[ip]]=(R[M[ip]]+M[ip+1])&MK; ip+=2
        elif op==3: a=M[ip]; R[a]=(R[a]-M[ip+1])&MK; zf=R[a]==0; ip+=2
        elif op==4: a=M[ip]; R[a]=(R[a]<<(M[ip+1]&31))&MK; ip+=2
        elif op==5: a=M[ip]; R[a]=(R[a]+R[M[ip+1]])&MK; ip+=2
        elif op==6: a=M[ip]; R[a]=(R[a]-R[M[ip+1]])&MK; zf=R[a]==0; ip+=2
        elif op==7: a=M[ip]; R[a]^=R[M[ip+1]]; ip+=2
        elif op==8: M[(ip+2+M[ip+1])&MK]=R[M[ip]]; ip+=2
        elif op==9: R[M[ip]]=M[(ip+2+M[ip+1])&MK]; ip+=2
        elif op in (10,11,12):
            t = zf if op==10 else (not zf if op==11 else True)
            ip = (ip+M[ip]-1)&MK if t else ip+1
        elif op==13: R[35]=inp[k]; k+=1
        elif op==14:
            p=ip+1+M[ip]; ip+=1
            while M[p]: out+=chr(M[p]&0xff); p+=1
        elif op==15:
            return [M[0x1ef7a+i] for i in range(35)],[M[0x1ef9d+i] for i in range(35)],out
