import sys,random; sys.path.insert(0,sys.argv[2]); from emu import run
import emu
b=[1]*35; A0,B0,o=run(b); print(o)
D=lambda x:[(a-bb)&0xffffffff for a,bb in zip(*run(x)[:2])]
d0=D(b)
cols=[]
for j in range(35):
    x=b[:];x[j]=2; cols.append([(u-v)&0xffffffff for u,v in zip(D(x),d0)])
# linearity check on random
for t in range(3):
    x=[random.randint(1,200) for _ in range(35)]
    pred=[(d0[i]+sum(cols[j][i]*(x[j]-1) for j in range(35)))&0xffffffff for i in range(35)]
    print('affine ok' if pred==D(x) else 'NOT affine')
import pickle; pickle.dump((d0,cols),open(sys.argv[2]+'/lin.pkl','wb'))
