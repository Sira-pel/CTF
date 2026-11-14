# Ferry Sus (REV 017) — solved

**Flag:** `LMC{one_forged_fare_crossed_the_river}`

## Target
- `player.zip` → `ferry-inspect` (stripped Rust PIE) + `route.bin` (`FSR2`, 10 records).
- Local: `./ferry-inspect route.bin PASS_HEX [GATE_HEX]` → `BOARDING PASS ACCEPTED`.
- Remote: `nc 47.131.225.172 31706`. Commands: `GATE`, `SUBMIT <pass_hex>`, `PLAIN`, `HELP`, `QUIT`. `GATE` is per connection; stage 10 mixes it in.

## Pass layout
`FJ\n\x00` plus 10 sections. Section: `FS`, stage (1..10), count n (1..8), X u16, H u8, 0, then n u16 deltas `2*n+8*k` and n 10-byte slots `(op, tag, C u16, imm u32, D, 0xa5^op^tag)`.

## VM
Record 0 is plaintext. After stage k commits, record k is XOR-decrypted with xorshift32 seeded by `key ^ 0x46455252` (`FERR`). Commit key = `(hash(imm,C) ^ acc) * 0x9e3779b1`. Hash is a chained FNV (`^= imm; C ^ ROL(edi*0x1000193, 5)`), init = opcode-13 immediate. Opcode 10 is an invertible 32-bit mixer (4 variants). The free last entry is unmixed so opcode 12 matches; earlier entries are pinned by opcode 16.

## Stages that are not just the mixer
- 7 and 9, opcode 24: `pow(lane[tag] % lane[lo], integer_from_D, lane[lo]) == lane[hi]`. Lanes come from opcode 23. Exponent is the D bytes little-endian (heap padding on the dword slots happened to be 0). Solved by Pohlig–Hellman. Stage 7 modulus `0x3690f25c3bb` (order a 41-bit prime, log fits in 40 bits). Stage 9 modulus `0xf1e8add1c3895eb` (smooth `p-1`).
- 8, opcode 25: product of two u32 values packed from D[0..3] and D[4..7] equals lane 0. Lane factors as `2521426997 * 3355721207`.
- 10, opcode 22: `acc = imm XOR gate` before the mixer. Gate `0` passes locally; the remote gate has to be folded in before `SUBMIT`.

Solver: `Lancang_Mekong_CTF_comp/solved/rev_ferrysus/solve_ferry.py`.

## Better approach (2026 retro)

Same lesson as `ferrysus.md`: reach the validated VM model via `unicorn`/`qiling` emulation
rather than hand-porting, and solve the mixer/pinned-entry constraints with angr/z3. The
Pohlig–Hellman (stages 7/9) and u32 factoring (stage 8) steps were correct and fast — the
only slow part was deriving opcode semantics, which emulation removes.
