# HILLarious (HTB, rev, Medium)

**Flag:** `HTB{h1ll_crypt0syst3m_1s_v3ry_int3rr3st1ng!!!}`

## Summary
`ransom` is a UPX-packed, stripped ELF. I unpacked it with the official upx 4.2.4 release (static, downloaded to the scratchpad); `upx -d` was enough.
The tool is invoked as `ransom encrypt <file>` and writes `<file>.enc`.

## .enc format
`"SNAR" | u64 seed (time()) | u32 orig_len | u32 1 | data`

## Key schedule (all derived from the stored seed)
- `h = FNV-1a64(seed bytes LE) ^ 0xdeadbeefcafebabe`. The XOR key is the 8 LE bytes of `h`.
- LCG (PCG constants, mul `0x5851f42d4c957f2d`): `s1 = h*A + 0x6c576fac43fd007c`, then `s_{n+1} = s_n*A + 0x14057b7ef767814f`.
- Matrix `[m0 m1; m2 m3] = [s1|1, s2, s3, s4|1]` (low bytes). If det is even, `m0 += 2`. Encryption needs det to be a unit mod 256.

## Encrypt / decrypt
Encrypt: pad to even length with 0x01, Hill 2×2 mod 256 on byte pairs, then XOR with the 8-byte key.
Decrypt (`exercises/rev/hillarious/decrypt.py`): XOR, multiply by the inverse matrix mod 256, truncate to orig_len.

## Lesson
Ransomware that stores its seed in the file header is fully reversible. Packed + stripped binary: unpack first, then the code is short. Imports only (`time`, no `rand`) pointed to a custom PRNG.
