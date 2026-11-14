# Intern (Team_Work 031, 700)

Flag format: `LMC{word_word_word}` (three lowercase English words). Not solved yet.

## Image

`intern_v3.zip` → `evidence/triage_storage.raw` (128MB).

DOS MBR, partition 1 FAT32 at sector 2048, label `SEC_STOR`, volume id `0x4B3A8F12`, cluster 1024.

## Recovered files

Deleted (0xE5) on `Users/mey/Desktop`:

- `AUDIT_TE.EXE` (inode 109, 24576) — MinGW PE32+ x64, stripped. Middle of the image (file `0x2000–0x4800`, includes part of `.text` and the start of `.rdata`) is zeroed.
- `NOTES_DR.TXT` (inode 110) — staging memo.

Other files are decoys (photos, SOP/policy/incident docx, ticket pdf, xlsx). Embedded `LMC{..._decoy...}` strings are canaries.

## Notes (real content)

- Author / external handle: Boromey `<sec-audit@internal.corp>`
- Station `WS-CHRONOS-04`, sector `KH-SR-01`, profile `apac_sr01`
- Container: AES-256-GCM, nonce 12, tag 16
- Salt string: `VOL-4B3A-8F12`
- Master keyphrase is **not** on the disk: “offsite personal emergency channel”
- Ticket `0000263006` requester: `meyyyyissadgirl`

## Unlinked memory fragment

Free clusters ~55038+ are a loaded-image copy of the wiped `.data` tail + `.rdata` (absolute offset `0x37bf800`).

- `0x37bf800` for `0x270` bytes: high entropy (likely vault ciphertext), then Mingw ctor/reloc pointers
- `.rdata` at `0x37bfc00` (VA `0x140006000`): status strings, SHA-256 padding/K/IV, 8-byte XOR key

XOR key at VA `0x140006200`: `5a a5 3c c3 69 96 55 aa`

Stack strings in `audit.exe` decode (rsp 16-aligned, first byte XOR `0x5a`, rest XOR `key[(addr)&7]`) to:

- HMAC key (16): `ChronosDriftVau3`
- info prefix: `CHRONOS_TELEMETRY_DISPATCH_v3:`

## Key derivation (from the surviving code)

`0x140002470` / `0x140002180`:

1. `DK = PBKDF2-HMAC-SHA256(password, salt, iterations=250000, dkLen=32)`
2. `PRK = HMAC-SHA256(key="ChronosDriftVau3", msg=DK)`
3. `OKM = HMAC-SHA256(key=PRK, msg=info || 0x01)` where `info = "CHRONOS_TELEMETRY_DISPATCH_v3:" + argv_context`

Likely argv: password = offsite keyphrase, salt = `VOL-4B3A-8F12`, context = `KH-SR-01`.
OKM is a 32-byte AES-256 key. The function wipes it and returns 0; GCM decrypt lived in the zeroed code.

AES-GCM open failed for the persona passwords. Rechecked 2026-11-11: the nonzero runs are 501 bytes at `0x37bf800` and 134 bytes at `0x37bf9f6` (a zero byte between them). Same OKM `c1fca948…aa8ea400` for `meyyyyissadgirl` / `VOL-4B3A-8F12` / `KH-SR-01`. Tried those two runs and their concatenation, nonce layouts n|ct|tag, n|tag|ct, ct|tag|n, ct|n|tag, AAD none plus the station strings, keys OKM/DK/PRK. No plaintext.

## Persona

- GitHub `boromeychan` (created 2026-05-09, bio exactly `meyyyyissadgirl`, 0 repos/gists)
- Telegram channel `@boromeychan`, title `មុីមុី`, 2 subscribers, only the default “Channel created” post (2024-05-25). No description. Profile photo is a polaroid with an Instagram watermark; no EXIF, no trailing bytes, no readable LSB. Yandex reverse search returned no source page. `@meyyyyissadgirl` is a contact page with an empty public bio.
- `boromey.bsky.social` exists but has 0 posts and looks unrelated.

## Still missing

The offsite keyphrase (or a different ciphertext/nonce layout). Decoys are not the flag.
