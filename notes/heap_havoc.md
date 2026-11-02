# Heap Havoc (picoCTF 2026, Binary Exploitation, Hard)

**Target:** chatelaine.cylabacademy.net 15334 (official instance)
**Flag:** `academy{h34p_0v3rfl0w_cc92348f}`

## Bug
`main` mallocs two `struct internet` (12 bytes) and two 8-byte name buffers. Each name is copied with `strcpy` with no length check, so `name1` overflows into the next chunk, where `struct2` lives.

## Heap layout (32-bit glibc, 16-byte chunks)
- `name1` usable at offset 0 is 12 bytes.
- `struct2` user data begins at `name1+16`: priority `+16`, name pointer `+20`, callback `+24`.

## Exploit
1. Fill 12 bytes, then overwrite `struct2`:
   - name pointer = `0x0804c041` (unused `.bss` padding, writable, NUL-free)
   - callback = `winner()` = `0x08049206`
2. `strcpy(struct2->name, argv[2])` writes `x` to the safe address.
3. `if (struct2->callback) callback()` calls `winner()`, which prints the flag.

Payload script: `Heap/exploit.py`. Input sent to the service: payload + ` x`.

## Notes
- No 32-bit libc locally, so the layout was reasoned from glibc and verified only on the remote instance.
