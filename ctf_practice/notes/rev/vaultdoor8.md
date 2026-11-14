# vault-door-8 (picoCTF 2019, Reverse Engineering, Hard)

## Approach
`VaultDoor8.java` reads a password, strips the wrapper (`substring(8, len-1)`
removes the `picoCTF{` prefix and trailing `}`), scrambles it bit-by-bit via
`scramble()`, and compares against a hardcoded `expected` byte array.

`scramble()` applies a fixed sequence of `switchBits(c, p1, p2)` calls per
character, swapping bit positions p1 and p2. Since swapping two bits twice
returns them to their original place, `switchBits` is its own inverse.

To invert `scramble()`: apply the same 8 swap operations to each expected
byte, but in **reverse order**:

Forward order: (1,2),(0,3),(5,6),(4,7),(0,1),(3,4),(2,5),(6,7)
Inverse: reverse of the same list.

Script: inverted each byte of `expected[]`, got the flag body, then wrapped
it as `picoCTF{...}` per the `main()` substring logic.

## Flag
picoCTF{s0m3_m0r3_b1t_sh1fTiNg_14c0f2f11}
