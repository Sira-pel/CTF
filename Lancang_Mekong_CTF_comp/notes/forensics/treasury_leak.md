# Treasury Leak (forensics) — in progress

Flag format: `LMC{...}`

## Artifacts

- `email.msg`: gateway `GW-LON-TR-09`, queue stamp `1790103722` (2026-09-22 19:02:02 UTC), DKIM `bh=4f8b91a78e22c9c7f18b320d` (12 bytes, not a full SHA-256), signature truncated (`b=MEUCI...`).
- `shortcut.lnk`: machine `LAPTOP-TREAS-08`, volume serial `8F21-9B04`, label `C_DRIVE`.
  - Volume droid: `{A48F219B-0442-491A-8C11-00249B8F219B}`
  - File droid: `{E71C94B2-3E41-47A2-991F-8841C09B2E11}`
  - Birth droids match. VBA project id `{8841A48F}` is 8841 (file droid) + A48F (volume droid), which confirms little-endian GUID formatting.
- `ledger.xlsm`: veryHidden sheet `Offshore_Escrow_Audit` names Apex Horizon Escrow Ltd., George Town, Cayman Islands, ref `TX-2026-Q3-8841`, status `DECOUPLED_SHARD_ACTIVE`, amount 47200000.
- Ciphertext: `xl/embeddings/oleObject1.bin` (1112 bytes). Length matches nonce 12 + tag 16 + ciphertext 1084.

## Recipe (TreasuryReconcile)

```
Salt = SHA256(Gateway_ID & ":" & DKIM_Body_Hash)
IKM  = SHA256(Volume_Droid_GUID)
Info = "APEX_ESCROW_AUDIT_Q3_V1"
Key  = HKDF_SHA256(Salt, IKM, Info, 32)
AES-256-GCM, wire [Nonce:12][Tag:16][Ciphertext]
```

## Blocker

RFC 5869 HKDF-SHA256 + AES-256-GCM does not authenticate for the literal inputs above (either tag placement). The canonical key is `b69bdf34b7adb18d30fedbcaef81e911b59453c1df037a667b40cdd7fb80689b`. AES-GCM CTR with that key and nonce = the first 12 bytes was checked against a library round-trip (counter starts at 2) and the resulting keystream is random, including a full-buffer search for `LMC{`. Associated data cannot fix that key.

Also failed: GUID case/braces/URN/raw bytes, file droid, both GUIDs, machine id prefix, UTF-16, timestamp or ESMTP id `q3-8841-gw` in the salt, external nonce = the 12-byte `bh`, SP 800-108 / X9.63 stand-ins, and using either SHA-256 digest directly as the AES key.

Further passes with no `LMC{` in the keystream: every GUID group-case variant, UTF-16LE/BE GUID with an ASCII salt, uppercase hex digests as HKDF salt/IKM, real SHA-256 of the email body (hex and base64) as `DKIM_Body_Hash` under both in-file and `bh` nonces, ChaCha20-Poly1305, nonce lengths 8 and 16, tag lengths 4/8/12/16, the 32-byte droid used directly as an AES key, RC4, and a single-byte XOR mask before GCM. Blob SHA-256 is `677b92d3884a22b7a46d1f16ab4b8b554fcce05bc9272f05ded2bb3feb360938`.

## Restart (re-parsed, recipe rechecked)

The VBA source really is only that comment plus `GetAuditContext` / `VerifyDisbursementSchedule`. No slack in the MSG or vbaProject streams, no zip gap, no `LMC` in the clear. Email body is UTF-16LE and does not hash to `bh` (SHA-256 of the UTF-8 text is `5667a6ae5a15e2ca80fb542d44b6678e36394392e690d517d1501f80f748043d`). LNK target size `45820` does not match `ledger.xlsm` (`5974`); timestamps do match `1790103722`.

Rebuilt HKDF-SHA256 and got the same canonical key `b69bdf34…`. AES-GCM does not authenticate. CTR plaintext for that key, for hashed/unhashed and UTF-16 inputs, for big-endian GUID strings, for SP 800-108 / X9.63, for SHA-1/SHA-384 outer hashes, and for XOR-of-digests is indistinguishable from random (longest ASCII run ~11). Also no readable output from ChaCha20, NaCl secretbox, EAX/CCM/OCB/SIV, RC4, EVP_BytesToKey, or XOR with the email/VBA/sheet text.

The funds destination in the clear is Apex Horizon Escrow Ltd., George Town, Cayman Islands, ref `TX-2026-Q3-8841`, 47200000 USD. The `LMC{…}` string is still only inside `oleObject1.bin`, and the written recipe does not decrypt it.

## Session 2 (ground-up restart) — result: still blocked

Re-parsed everything from scratch, independently of the above. Confirmed:
- LNK TrackerDataBlock parsed per MS-SHLLINK (BlockSize 96, Length 88 = 16+32+32, Droid == DroidBirth).
- Volume droid `{A48F219B-0442-491A-8C11-00249B8F219B}`, file droid `{E71C94B2-3E41-47A2-991F-8841C09B2E11}`.
- MSG has exactly 4 property streams, no orphans, no slack; headers clean (hexdumped).
- OLE object is raw ciphertext (entropy 7.82, no OLE/ZIP magic), 1112 = 12+16+1084.
- VBA module fully decompressed: comment block + GetAuditContext + VerifyDisbursementSchedule only.
- No plaintext flag anywhere; not compressed (deflate/gzip/bz2/lzma all fail); not repeating-key XOR.

Verified tooling correctness: HKDF matches RFC 5869 TC1; AES-GCM round-trips and rejects bad tags.
So the failures are not implementation bugs.

Searched ~6M derivations, all with zero hits:
- GUID forms: LE/BE, all 8 endianness permutations of the 3 fixed fields, case, braces,
  \\?\Volume{}, urn:uuid:, UTF-8/UTF-16LE, raw bytes, hex; also all 263 16-byte LNK windows.
- Salts: gateway (`GW-LON-TR-09`, `q3-8841-gw`, lowercase), bh (literal/upper/raw bytes),
  separators `:` `-` `_` `|` ` ` etc., plus 7,044 token-pair combinations from all artifacts.
- KDF deviations: arg permutations of HKDF, extract-only, expand-only, HMAC orderings,
  concatenation hashes, PBKDF2(1/1000/10000), digest presentations raw/hex/HEX/base64.
- AEAD: all 6 nonce/tag/ciphertext orderings, nonce offsets 0-40, nonce lengths 4/8/12/16,
  tag at any offset in first 64 bytes, AAD variants, derived nonces, padded Info strings.
- Other primitives: CBC/CTR/CFB/OFB, ChaCha20/ChaCha20-Poly1305, RC4, AES-KW (RFC 3394),
  homemade SHA256-counter keystreams, SP800-108/X9.63 stand-ins, EAX/CCM/OCB/SIV.

Remaining untested lead: `bh=4f8b91a78e22c9c7f18b320d` is 12 bytes, not a valid SHA-256,
and it is not a truncated hash of the body under any canonicalization tried (raw/UTF-16/
CRLF/LF/simple/relaxed, sha256/sha1/md5). The VBA says "DKIM_Body_Hash", so the intended
input may be a value not literally present in the headers, OR the recipe has one more
undocumented twist. That is where to resume.

Working dir: Lancang_Mekong_CTF_comp/unsolved/forensics_treasury_leak/fresh (scratch scripts moved to fresh/scratch/).

## Session 3

Re-parsed MSG, LNK, and VBA from scratch. Streams, slack, and zip CRCs are clean. VBA source matches the recipe above with no hidden characters. Volume droid `{A48F219B-0442-491A-8C11-00249B8F219B}`, file droid `{E71C94B2-3E41-47A2-991F-8841C09B2E11}`, project id `{8841A48F}`.

Independent HKDF-SHA256 (RFC 5869, counter starts at 1) reproduces key `b69bdf34b7adb18d30fedbcaef81e911b59453c1df037a667b40cdd7fb80689b`. AES-256-GCM does not authenticate for either tag placement. CTR plaintext for that key is random (printable ratio ~0.38), including when the 12-byte nonce is taken from `bh` or slid across the blob. So this is a wrong key or a wrong cipher, not a missing AAD.

Also failed on that recipe family: UTF-16LE salt and GUID (with and without BOM/NUL), GUID `ToString("X")`, HKDF counter 0 and 4-byte counter, inner hash sha1/sha384/sha512/md5, hex-encoded HKDF output used as the AES key, external GUID as the GCM tag, AES-128 with the raw droid, PBKDF2 (1/4096/8841/10000), and alternate Info strings (`TX-2026-Q3-8841`, `DECOUPLED_SHARD_ACTIVE`, entity name). No `LMC{` anywhere in the clear; the only `LMC` text is the format line in README.

Clear destination remains Apex Horizon Escrow Ltd., George Town, Cayman Islands, ref `TX-2026-Q3-8841`, 47200000 USD. The `LMC{...}` sentence is still only inside `oleObject1.bin`.

## Session 4 (other ciphers)

Crib-checked about 7800 nearby keys (recipe HKDF, swapped HKDF, SHA256 of token pairs, raw droids) under AES-CTR/GCM, ECB, CBC, and ChaCha20. No plaintext starts with `LMC{`, `Apex`, `PK`, or `%PDF`. Repeating-XOR crib drag for `LMC{` / `Apex Horizon` also failed. Libsodium secretstream, XChaCha20-Poly1305, secretbox, and scrypt with the same inputs do not open the blob. Using the 32-character GUID hex itself as an ASCII AES key does not either. Null-terminated salt/GUID strings still decrypt to noise.

## Session 5

Full-buffer search, not just the first block: 1284 recipe keys and 2160 HKDF shape variants (counter width, role swap, no counter). No `LMC{`, `Apex`, `Cayman`, `George`, or `Horizon` anywhere in the plaintext. `bh` is not a prefix of SHA-256/SHA-1/MD5 of the msg, lnk, xlsm, ole blob, or VBA. NaCl sealed box and crypto_box, with seeds from the gateway string or the volume GUID, do not open the blob. Derived nonces (`SHA256(guid)[:12]`, `SHA256(salt)[:12]`) with the recipe key also stay random.
