# Magic Scrolls (HTB, Pwn, Hard): SOLVED

Flag: `HTB{052818e701e81a0d3574d63a7e91df69}`
Files: `exercises/pwn/magicscrolls/` (zip password `hackthebox`). Exploit: `exercises/pwn/magicscrolls/solve/exploit.py` (`python3 exploit.py REMOTE`)
Target: amd64, PIE, Full RELRO, canary, NX, glibc 2.37 (Debian). Allocations limited to 16, malloc size ≤ 0x1ff, no edit.

## Bug
- A wrong charm (anything other than `Alohomora`) sets `power = 4`. `update_magic_numbers` then writes to `magic_numbers[power]` and `[power+1]`, which alias `spells[0]` and `spells[1]` in .bss:
  - if `mn0 == mn2 == 0`, it zeroes the low byte of `spells[0]` (same for `mn1/mn3` → `spells[1]`)
  - otherwise it sets `spells[0] = mn0 & mn2` (set `mn2 = -1` to get an arbitrary pointer)
- `set_favorite_spell` re-fetches `spells[super_spell_set]` on every call, and `read_spell` prints `super_spell_len` bytes from it. With favorite = spell 1, this is an arbitrary read of 0xff bytes.
- `remove_spell(0)` frees `spells[0]` → arbitrary free. Freeing index 0 doesn't reset the favorite's length.

## Chain
1. Heap leak: spell0 (0x20), spell1 (0x110), favorite 1, free spell0. Null the low byte of `spells[1]` so it points to heap+0x200, then read: the tcache fd at +0xa0 equals `heap>>12`.
2. Spell `a` (0x1ff bytes) contains fake chunks: U (size 0x441, ends exactly on chunk `d`'s header after a/b/c), F (0x111), G (0x61, inside F), G2 (0x61). Then allocate b, c (0x30) and d (0x30).
3. Free U through the arbitrary free → unsorted bin. Reading its fd gives libc (fd − libc base = 0x1d3ce0).
4. Read `environ`. Scan down for read_spell's saved RIP (PIE+0x13a8). Its rbp equals create_spell's rbp (both are called from main), at env−0x198.
5. Free G2, G, F. Re-allocate F (0x100) to overwrite G's fd with `((&G)>>12) ^ rbp`. Then malloc G, then malloc → rbp. create_spell's memcpy writes `[junk][ret][pop rdi][/bin/sh][system]` above the canary. The function returns into the chain → shell.

## Gotchas
- pwntools `ROP()` cache crashes on Python 3.14 (`EXTENDED_ARG not allowed`): search the gadget bytes (`5f c3`) yourself.
- read_spell output: 52 bytes per line, separated by `:-:\n` + 21 spaces + `:-:` (28 bytes).
- PIE on WSL showed `0x65…`, so don't assume `0x55/0x56`.
