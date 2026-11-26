import struct
b=open('shadow_labyrinth','rb').read()
def rd(va,n): return b[va-0x2000+0x2000:va-0x2000+0x2000+n] if va<0x3000 else None
perm=list(b[0x22c0:0x22c0+48]); print('perm',perm)
tgt=struct.unpack('<12Q',b[0x20e0:0x20e0+96]); 
co=struct.unpack('<48Q',b[0x2140:0x2140+384])
for i in range(12): print(i,co[4*i:4*i+4],tgt[i])
print('iv',b[0x30c0:0x30d0].hex())
print(b[0x2000:0x20e0])
M=2**64
buf=[]
for i in range(12):
    a,b_,c,d=co[4*i:4*i+4]; T=tgt[i]
    L={}
    for x in range(256):
        for y in range(256): L.setdefault((a*x+b_*y)%M,[]).append((x,y))
    sols=[]
    for z in range(256):
        for w in range(256):
            k=(T-c*z-d*w)%M
            if k in L:
                for x,y in L[k]: sols.append((x,y,z,w))
    print(i,sols); buf+=list(sols[0])
inner=[0]*48
for j in range(48): inner[perm[j]]=buf[j]
print(bytes(inner)); open('/tmp/claude-1000/-home-pel-sira-ctf/6d150956-321d-4a48-88a0-8edc32d4685e/scratchpad/buf.bin','wb').write(bytes(buf))
