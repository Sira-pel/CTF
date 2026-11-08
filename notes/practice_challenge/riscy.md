# riscy business (picoMini by redpwn, Reverse Engineering, Hard)

## Setup
- Binary is a statically linked, stripped RISC-V64 (RVC, double-float ABI) executable
  with no libc (raw syscalls only).
- Tooling: `objdump` has no RISC-V binutils backend installed, but `radare2`/`r2`
  auto-detects `asm.arch=riscv` and disassembles fine. `qemu-riscv64` runs it directly
  for dynamic testing.
```bash
file riscy
r2 -q -e bin.relocs.apply=true -c "aaa; pdf @ entry0" riscy
qemu-riscv64 ./riscy          # to test input interactively
```

## Logic (all inlined in `entry0`, no libc)
1. Prints prompt, reads a line from stdin via raw `read` syscalls into a stack buffer
   (max 64 bytes), stopping at `\n`.
2. Requires length > 8 (`You need to take some more riscs than that.` otherwise).
3. Takes the **first 8 bytes of the input as an RC4 key** (`fcn.00010080` is the
   classic RC4 KSA: fills S-box 0..255, key-schedules with the 8-byte key; the 2 bytes
   right after the 256-byte S-box in memory are the persistent `i`/`j` PRGA counters).
4. `fcn.000100d2` is the RC4 PRGA (keystream byte generator).
5. The entry loop XORs **the entire input (including the 8 key bytes themselves)**,
   except the trailing `\n`, with the RC4 keystream, in place — i.e.
   `ciphertext = RC4(key=input[0:8], input[0:len-1])`.
6. Compares the result against a 52-byte blob embedded in `.rodata` at file offset
   `0x210` (`vaddr 0x10210`, since `PT_LOAD` maps `vaddr 0x10000` to file offset `0`).
   Match -> `Success!`, mismatch -> `That was a bit too riscy for me!`.

## The trick
The RC4 key is the plaintext's own first 8 bytes, but the keystream only depends on
the key (not the rest of the plaintext), so guessing the first 8 characters lets you
decrypt the rest, then check the decrypted first 8 bytes match your guess
(self-consistency). `picoCTF{` is exactly 8 characters — the obvious guess — and it
works.

## Solve script
```python
with open('riscy','rb') as f:
    data = f.read()
blob = data[0x210:0x210+52]

def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for c in data:
        i = (i+1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i]+S[j]) % 256]
        out.append(c ^ k)
    return bytes(out)

print(rc4(b'picoCTF{', blob))
# -> b'picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl8xyMUlpgvz}'
```

## Verification
```bash
printf '%s\n' 'picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl8xyMUlpgvz}' | qemu-riscv64 ./riscy
# -> Success!
```

## Flag
`picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl8xyMUlpgvz}`
