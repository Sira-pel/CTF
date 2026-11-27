#!/usr/bin/env python3
"""Godot 4.x PCK (format v2) key recovery + extraction, no external Godot tools.

  python3 -I godot_pck.py findkey <game.exe> <game.pck>        # ~40 s for a 44 MB exe
  python3 -I godot_pck.py unpack  <game.pck> <outdir> [hexkey]  # key needed if encrypted

Layout (v2): "GDPC" | u32 ver=2 | u32 major,minor,patch | u32 pack_flags | u64 file_base
             | 16*u32 reserved | u32 file_count @0x60 | directory @0x64
pack_flags & 1 => directory encrypted. Entry: u32 path_len | path | u64 ofs (+file_base)
             | u64 size | md5[16] | u32 flags (flags & 1 => file encrypted).
Encrypted blob: md5(plain)[16] | u64 plain_len | iv[16] | AES-256-CFB ciphertext (16-aligned).
Godot 4.x exports keep .gd as plain source (3.x / some 4 exports use .gdc bytecode -> gdsdecomp).
Embedded PCK (single exe): look for "GDPC" near the end of the exe and parse from that offset.
"""
import sys, struct, hashlib, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def aes_cfb(key, iv, ct):
    return Cipher(algorithms.AES(key), modes.CFB(iv)).decryptor().update(ct)


def blob(buf, p, key):
    md5, ln, iv = buf[p:p+16], struct.unpack('<Q', buf[p+16:p+24])[0], buf[p+24:p+40]
    pt = aes_cfb(key, iv, buf[p+40:p+40+((ln+15)//16)*16])[:ln]
    if hashlib.md5(pt).digest() != md5:
        raise ValueError('MD5 mismatch (wrong key?)')
    return pt


def findkey(exe_path, pck_path):
    exe, pck = open(exe_path, 'rb').read(), open(pck_path, 'rb').read()
    iv, probe = pck[0x7c:0x8c], pck[0x8c:0x9c]
    for off in range(0, len(exe) - 32, 4):          # key is a 4/8-aligned global
        k = exe[off:off+32]
        if k.count(0) > 8:
            continue
        pt = aes_cfb(k, iv, probe)
        if b'res:' in pt and struct.unpack('<I', pt[:4])[0] < 512:
            try:
                blob(pck, 0x64, k)
            except ValueError:
                continue
            print(f'key @ exe+{off:#x}: {k.hex()}')
            return k
    print('no key found (try alignment 1, or an embedded PCK offset)')


def unpack(pck_path, out, hexkey=None):
    pck = open(pck_path, 'rb').read()
    assert pck[:4] == b'GDPC', 'not a PCK'
    flags, base = struct.unpack('<IQ', pck[0x14:0x20])
    n = struct.unpack('<I', pck[0x60:0x64])[0]
    key = bytes.fromhex(hexkey) if hexkey else None
    d = blob(pck, 0x64, key) if flags & 1 else pck[0x64:]
    p = 0
    for _ in range(n):
        l = struct.unpack('<I', d[p:p+4])[0]
        path = d[p+4:p+4+l].rstrip(b'\0').decode(); p += 4 + l
        ofs, size = struct.unpack('<QQ', d[p:p+16]); p += 32
        fl = struct.unpack('<I', d[p:p+4])[0]; p += 4
        data = blob(pck, base+ofs, key) if fl & 1 else pck[base+ofs:base+ofs+size]
        dst = os.path.join(out, path.replace('res://', '').lstrip('/'))
        os.makedirs(os.path.dirname(dst) or out, exist_ok=True)
        open(dst, 'wb').write(data)
        print(fl, size, path)


if __name__ == '__main__':
    {'findkey': findkey, 'unpack': unpack}[sys.argv[1]](*sys.argv[2:])
