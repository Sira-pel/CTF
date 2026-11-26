import zlib,struct,sys
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
S=sys.argv[1]
buf=open(S+'/buf.bin','rb').read(); b=open('shadow_labyrinth','rb').read()
iv=b[0x30c0:0x30d0]; d=bytearray(open('file.bin','rb').read())
for i in range(len(d)): d[i]^=buf[32+(i&15)]
dec=Cipher(algorithms.AES(buf[:32]),modes.CBC(iv)).decryptor()
p=dec.update(bytes(d))+dec.finalize(); p=p[:-p[-1]]
code=zlib.decompress(p); open(S+'/code.bin','wb').write(code); print(len(code))
# handler table
print([hex(x) for x in struct.unpack('<17Q',b[0x2ce0:0x2ce0+0x88])])
