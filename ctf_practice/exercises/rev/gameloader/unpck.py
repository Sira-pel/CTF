import sys, struct, hashlib, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
K = bytes.fromhex('f2f44f0aaa282c6b66065b1ca437abae05e20a55a0f6b2fd85f5b90576f0c88f')
pck = open(sys.argv[1],'rb').read(); out = sys.argv[2]
def dec(buf, p):
    md5 = buf[p:p+16]; ln = struct.unpack('<Q', buf[p+16:p+24])[0]; iv = buf[p+24:p+40]
    ct = buf[p+40:p+40+((ln+15)//16)*16]
    pt = Cipher(algorithms.AES(K), modes.CFB(iv)).decryptor().update(ct)[:ln]
    assert hashlib.md5(pt).digest()==md5; return pt
base = struct.unpack('<Q', pck[0x18:0x20])[0]; n = struct.unpack('<I', pck[0x60:0x64])[0]
d = dec(pck, 0x64); p = 0
for _ in range(n):
    l = struct.unpack('<I', d[p:p+4])[0]; path = d[p+4:p+4+l].rstrip(b'\0').decode(); p += 4+l
    off, size = struct.unpack('<QQ', d[p:p+16]); p += 16+16; fl = struct.unpack('<I', d[p:p+4])[0]; p += 4
    data = dec(pck, base+off) if fl & 1 else pck[base+off:base+off+size]
    dst = os.path.join(out, path.replace('res://',''))
    os.makedirs(os.path.dirname(dst) or out, exist_ok=True); open(dst,'wb').write(data)
    print(fl, size, path)
