# Wayback (HTB, rev, Easy)

**Flag:** `HTB{T1me_0n_the_B1t5_1386784885}`

## Summary
`V1` is a C++ password generator. `decrypt.py` holds an AES-256-CBC blob (IV‖CT) and takes the generated password as the key, NUL-padded to 32 bytes.

## Generator (`generate_password(int len, bool sym, bool num)`)
- Charset: `a-z` + `A-Z`, then `!@#$%^&*_+` if sym, then `0-9` if num. With both set it is 72 chars.
- Seed comes from `localtime(time(0))`, using 32-bit wrapping int math:
  `sec + min*100 + hour*1e4 + mday*1e6 + (mon+1)*1e8 + (year+1900)*1e10`
- Each char is `cs[rand() % len(cs)]` (glibc `rand`).

## Solve
Brute-forced every second of 2013-12-10 and 2013-12-11 (172,800 seeds) × the 4 charset options. glibc `rand` was called through ctypes, and a seed counts as a hit when the plaintext contains `HTB`.
The hit was sym+num at 2013-12-11 13:01:25, password `eWXtk*Oe%j5cof7Od08G`. Solver: `exercises/rev/wayback/solve.py`.

## Lesson
A time-seeded `srand` with a known date window means a tiny keyspace. Copy the seed formula exactly, including int32 overflow, and the charset order.
