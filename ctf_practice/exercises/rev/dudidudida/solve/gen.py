import sys
exec(open(sys.argv[3]).read())
out=[]
L=lambda x:[(x>>(64*i))&((1<<64)-1) for i in range(4)]
out.append('#define N 224\n#define START %d\n#define WINC %d'%(START,WINC))
out.append('static const unsigned long long MM[4]={%s};'%','.join('%dULL'%v for v in L(M)))
out.append('static const unsigned long long HH[N][4]={%s};'%','.join('{%s}'%','.join('%dULL'%v for v in L(H[i]%M)) for i in range(224)))
out.append('static const unsigned long long CV[N][4]={%s};'%','.join('{%s}'%','.join('%dULL'%v for v in L(cells[i]['cv'] or 0)) for i in range(224)))
out.append('static const int ISCP[N]={%s};'%','.join('1' if cells[i]['cv'] is not None else '0' for i in range(224)))
# edges: E[u][d] = target, -1 fail, -2 win
out.append('static const int E[N][4]={%s};'%','.join('{%s}'%','.join(str(cells[i]['e'].get(d,-1) if cells[i]['e'].get(d)!='WIN' else -2) for d in range(4)) for i in range(224)))
# map: MP[u][d] code 0..3 or -1 if no remap
out.append('static const int MP[N][4]={%s};'%','.join('{%s}'%','.join(str(int(cells[i]['map'][d],2)) if cells[i]['map'] else '-1' for d in range(4)) for i in range(224)))
open(sys.argv[4],'w').write('\n'.join(out)+'\n')
