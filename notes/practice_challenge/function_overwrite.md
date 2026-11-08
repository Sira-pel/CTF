# function overwrite (Binary Exploitation, Hard, picoCTF 2022 / cylabacademy)

**Flag:** `academy{0v3rwrit1ng_P01nt3rs_80c6cb42}`

## Bug
`vuln()` does `if (num1 < 10) fun[num1] += num2;` with no lower bound, so a negative `num1` writes before the `fun` array.
In the non-PIE 32-bit binary, `check` (0x0804c034) sits exactly `fun[-11]` (fun = 0x0804c060).

## Exploit
- Story must sum to 1337 (`easy_checker`): `zzzzzzzzzzu` = 10*122 + 117 = 1337.
- Shift `check` from `hard_checker` (0x0804936e) to `easy_checker` (0x08049238): delta = -310.
- Input: `zzzzzzzzzzu` then `-11 -310`.

Remote: `nc chatelaine.cylabacademy.net 38428`. Single run, no fuzzing.
Source: `Function_overwrite/vuln.c`.
