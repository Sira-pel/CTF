# GameLoader (HTB, rev, Medium)

**Flag:** `HTB{Und3t3ct3d_GD_M@lw4r3_PCB29543}`

## Summary
The download is a Godot 4.1.1 Windows game (`Platformer 2D.exe` + `.pck`). The PCK is format v2 with flag 1, meaning its directory is encrypted (AES-256-CFB). `player.gd` holds a downloader trojan.

## Steps
1. **Find the PCK key.** The encrypted directory sits at 0x64 as md5, u64 length, 16-byte IV, then ciphertext. I tried every 4-aligned 32-byte window in the exe as an AES key and checked for `res://` in the decrypt, then verified the MD5. The key is at file offset 0x1ed5680: `f2f44f0aaa282c6b66065b1ca437abae05e20a55a0f6b2fd85f5b90576f0c88f`. Script: `findkey.py`, about 40 s.
2. **Extract.** `unpck.py` reads the directory entries (path_len, path, ofs+file_base, size, md5, flags). It decrypts entries with flags&1, which use the same md5/len/iv layout. In 4.1 exports the `.gd` files are plain source.
3. **Deobfuscate `player.gd`.** `_ready` builds int arrays (`deob.py` replays them in order). It decodes to:
   - C2 `g4m3l0ad3r-network.htb`: `POST /enum` with sysinfo JSON, then `GET /p47l0ad_binary` with a `Cookie:` header. The cookie is `"".join(int array)`, i.e. a decimal digit string.
   - `loap` base64-decodes to `GD_M@lw4r3_PCB29543}`, which is **part 2**. Its MD5 is passed as an argument to the downloaded `new_level_mod.exe`.
4. **C2 = challenge instance.** The `GET /p47l0ad_binary` response header `X-Half-Flag: HTB{Und3t3ct3d_` is **part 1**. The payload itself is only a sysinfo collector (`C:\Temp\system_report.txt`).

## Lesson
Godot encrypted PCK: brute-force the key over the exe's 32-byte windows and verify with the stored MD5. Check C2 response *headers*, not only the body.
