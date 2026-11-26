import pickle,sys
from fractions import Fraction as F
d0,cols=pickle.load(open(sys.argv[1]+'/lin.pkl','rb'))
sg=lambda v: v-2**32 if v>=2**31 else v
A=[[F(sg(cols[j][i])) for j in range(35)] for i in range(35)]
# D(x)=d0+sum A(x-1)=0  -> A x = sum_j A_ij - d0
b=[sum(A[i])-sg(d0[i]) for i in range(35)]
print('max coef',max(abs(c) for r in A for c in r))
n=35;M=[A[i]+[b[i]] for i in range(n)]
for c in range(n):
    p=next(r for r in range(c,n) if M[r][c]!=0); M[c],M[p]=M[p],M[c]
    for r in range(n):
        if r!=c and M[r][c]!=0:
            f=M[r][c]/M[c][c]; M[r]=[a-f*bb for a,bb in zip(M[r],M[c])]
x=[M[i][n]/M[i][i] for i in range(n)]; print(x)
print(bytes(int(v)%256 for v in x))
