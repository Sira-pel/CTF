import ctypes, itertools
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
libc = ctypes.CDLL("libc.so.6")
ct = bytes.fromhex('ad24426047b0ffb03b679773664838462a6f00bdcaf0589dd1748e9ed5c568601edc87d974894f9dd9b98cc35535145c494eb0af84c8f78d440a033c91c7de62d506d8cabdc2a10138b95139bbe60e89')
iv, c = ct[:16], ct[16:]
lo="abcdefghijklmnopqrstuvwxyz"; up=lo.upper(); sym="!@#$%^&*_+"; dig="0123456789"
for cs_name, cs in [("sym+num", lo+up+sym+dig), ("sym", lo+up+sym), ("num", lo+up+dig), ("none", lo+up)]:
  for day in (10,11):
    for h,m,s in itertools.product(range(24),range(60),range(60)):
      seed = (s + m*100 + h*10000 + day*1000000 + 12*100000000 + 2013*10000000000) & 0xffffffff
      libc.srand(seed)
      pw = "".join(cs[libc.rand() % len(cs)] for _ in range(20))
      d = Cipher(algorithms.AES(pw.encode().ljust(32,b'\0')), modes.CBC(iv)).decryptor()
      pt = d.update(c)+d.finalize()
      if pt.startswith(b"HTB{") or b"HTB" in pt:
        print(cs_name, f"2013-12-{day} {h:02}:{m:02}:{s:02}", pw, pt); raise SystemExit
