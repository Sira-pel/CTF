# Gatekeeper (picoCTF 2026, Reverse Engineering, Medium) — SOLVED

**Target:** `nc chatelaine.cylabacademy.net 12375`
**Binary:** [`ctf_practice/gatekeeper/gatekeeper`](../../ctf_practice/gatekeeper/gatekeeper) — x86-64 PIE, not stripped. (File mode is not executable; run via `/lib64/ld-linux-x86-64.so.2 ./gatekeeper`.)

## Logic
- `main` reads a token with `scanf("%31s")`.
- If `is_valid_decimal` (ctype 0x800 = isdigit), value = `atoi`; else if `is_valid_hex` (ctype 0x1000 = isxdigit), value = `strtol(s, 16)`; else "Invalid input".
- Gate: value must satisfy `999 < v <= 9999`, and `strlen(input) == 3`.
- Decimal inputs of length 3 are at most 999, so the only way through is a 3-digit **hex** value >= 0x3e8.
- `reveal_flag` reads `/flag.txt`, prints it reversed, with filler text inserted.

## Solve
- Input `3e8` passes the gate (1000).
- Server output: `Access granted: }61aftc_oc_ipf7deftc_oc_ip...`. Removing the filler `ftc_oc_ip` and reversing gives the flag.

## Flag
`academy{3_digit_hex_GT_999_fed7fa16}`
