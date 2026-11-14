# Keygenme (picoCTF 2022, Reverse Engineering, Hard)

## Approach
- `file`/`strings` on the stripped x86-64 PIE binary showed fragments of an embedded
  string ("academy{", "br1ng_y0", "g_y0ur_0") built via overlapping `movabs` stores,
  plus imports for `libcrypto` (MD5) and `sprintf`/`fgets`.
- Disassembled the validation routine with `objdump -d -M intel`.

## Algorithm
1. Builds base string `academy{br1ng_y0ur_0wn_k3y_` (27 bytes) via overlapping 8-byte
   immediate writes (clever byte-level splicing, e.g. `"br1ng_y0"` + `"g_y0ur_0"`
   overlapped by 4 bytes -> `"br1ng_y0ur_0"`).
2. Builds a second 1-char string `}`.
3. Computes `MD5(base_string)` -> 16 raw bytes -> hex-encoded to a 32-char string via
   a `sprintf("%02x", byte)` loop.
4. Computes `MD5("}")` similarly (hex string computed but turned out unused in the
   final comparison).
5. Builds the expected 36-byte license key as:
   `base_string (27 bytes)` + 8 hex chars pulled from specific indices of the
   `MD5(base_string)` hex string (indices `21,21,0,15,5,11,8,8`) + literal `}`.
6. `main` reads a line via `fgets` (be careful: keep no trailing newline when testing
   via a pipe — `strlen` must equal exactly 36) and compares it byte-for-byte to the
   constructed buffer.

## Solve script
```python
import hashlib
s = 'academy{br1ng_y0ur_0wn_k3y_'
h = hashlib.md5(s.encode()).hexdigest()
idx = [21,21,0,15,5,11,8,8]
suffix = ''.join(h[i] for i in idx)
key = s + suffix + '}'
print(key)
```

## Verification
```
printf '%s' 'academy{br1ng_y0ur_0wn_k3y_bb724f88}' | ./keygenme
# -> That key is valid.
```

## Flag
`academy{br1ng_y0ur_0wn_k3y_bb724f88}`
