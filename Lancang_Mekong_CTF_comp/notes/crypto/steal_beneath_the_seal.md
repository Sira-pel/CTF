# Silt Beneath The Seal

Crypto. `nc 47.131.225.172 16656`. File: `instance.json` (title "Silt Happens").

## Hidden offset

`b_i = a_i * (anchor + h) + e_i (mod M)`, `|e_i| < 2^30`, `0 <= h < 2^44`, `M` is 176 bits.

Direct inversion of two samples gives unrelated 175-bit values, so the error term is real. One 10-dimensional Kannan lattice on 8 samples (error columns scaled by `2^44`, secret column by `2^30`) produced

`h = 1171995462696`

Every one of the 34 samples then lands inside the error bound (max `|e| = 1039896872`).

## Silt lock

`hidden_parameter = anchor + h` (not `h` alone). Stones:

`stone_i = SHA256(min_be(hidden_parameter) || b"|silt-lock-stone-v2|" || salt || uint16_be(i)) mod 2^54`

with `salt` hex-decoded. The mask is the 58-bit subset whose stones sum to `target` modulo `2^54`. There are 11 such subsets; `mask_sha256` selects `0x02c490bde29513d6` (8-byte little-endian bitset).

XOR-ing stones instead of adding them does not match the hash. Stones derived from `h` alone, or from the ASCII hex salt, do not open the capsule.

## Capsule

`AES-256-GCM` key = `SHA256(min_be(hidden_parameter) || b"|silt-vault-v2|" || mask_bytes)`.

Plaintext: `{"token":"SILT-4cac48ec2a8f57813aa94ca33fa1df02"}`.

`SUBMIT SILT-4cac48ec2a8f57813aa94ca33fa1df02` → `LMC{dredged_the_token_from_the_silt}`.
