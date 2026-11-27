import sys, struct, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
exe = open(sys.argv[1],'rb').read(); pck = open(sys.argv[2],'rb').read()
md5 = pck[0x64:0x74]; ln = struct.unpack('<Q', pck[0x74:0x7c])[0]; iv = pck[0x7c:0x8c]
ct = pck[0x8c:0x8c+((ln+15)//16)*16]
probe = ct[:16]
# fast filter: first decrypted u32 is path_len (small), path starts with "res://"
for off in range(0, len(exe)-32, 4):
    k = exe[off:off+32]
    if k.count(0) > 8: continue
    pt = Cipher(algorithms.AES(k), modes.CFB(iv)).decryptor().update(probe)
    if pt[4:10] == b'res://' or (struct.unpack('<I',pt[:4])[0] < 300 and b'res:' in pt):
        full = Cipher(algorithms.AES(k), modes.CFB(iv)).decryptor().update(ct)[:ln]
        print(hex(off), k.hex(), hashlib.md5(full).digest()==md5); break
