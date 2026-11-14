# Powershelly (picoCTF 2021, Reverse Engineering, Hard)

**Decoded flag:** `academy{2018highw@y_2_pow3r$hel!}`
(The decoded bytes literally start with `academy{`. The matrix note used `picoCTF{...}`, so if the platform rejects this, try the `picoCTF{` prefix with the same body.)

## Challenge
`rev_PS.ps1` turns an `input.txt` into `output.txt` (264 int64 values). Goal: recover the input.

## Solution (work backwards, per hint 1)
1. Input is 5 rows x 264 groups of 6 bits. Column j (5 groups x 6 bits) is concatenated into a 30-bit `block[j]`.
2. `Scramble(block, seed=(j+1)*127%500)` places bit i at slot `(i*seed)%30` (linear probe to the next free slot), writing each bit as `11` or `00`. The result is a 60-bit int64.
3. Chain: `result_j = fun_j ^ result_{j-1} ^ rand_j`, with `rand_j = (((j+1)*327 % 681) + 344) % 313`. The output file stores each `result_j`.
4. Inversion (`solve.py`): `fun_j = out_j ^ out_{j-1} ^ rand_j`, then re-run the slot permutation and read back the bit from each `11`/`00` pair to get the 30-bit block, then rebuild the 5x6 glyph.
5. Only two distinct 5x6 glyphs appear, so each one is a bit. The 264 bits make 33 ASCII bytes, which give the flag above.

## Takeaway
Writing the obfuscation as an invertible pipeline and inverting each stage in reverse order is quick. The glyph bitmaps were just a bit-per-block disguise.
