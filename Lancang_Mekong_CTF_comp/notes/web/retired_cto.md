# Retired CTO (web, 500 pts) — IN PROGRESS, not solved

## Targets (official challenge hosts only)
- Share: https://lancang-share-rsk.ctf-challenges.xyz/ (PHP, login.php, logout.php; robots.txt only)
- Chat: https://lancang-chat.ctf-challenges.xyz/ ("Teamline", better-auth, SPA; /login, /c/<id>, /search)

## Findings
- Given creds rsk.hr / 3e8d0e41174c1c68 are Chat creds, NOT Share creds.
  - Chat: sign in with username `rsk.hr` (login UI rewrites it to `rsk:hr` before POST to /api/auth/sign-in/username). Works. User = Sophea Hout (Head of People, team rsk).
  - Share login.php: rejects rsk.hr and rsk:hr ("Invalid credentials.").
- Share login: single-quote probe gives no SQL error (weak SQLi hypothesis, not confirmed).
- CTO = Seng Pakrenha (Chat DM). SecurityBot scans every link sent to him:
  - Blocked categories seen: "credential keywords" (login pages not allowed), "obfuscated script".
  - Blocked content is recorded and quarantined.
- Earlier DM attempts (before this session) used third-party tunnel hosts (*.lhr.life). That breaks the CTF network rule (no non-official hosts). Do not repeat.

## Open question (needs user approval)
- Winning path likely needs a message to Seng that passes SecurityBot and gets him to act. Sending new lure messages to the CTO and any scanner-evasion testing is not done yet.

## Teammate handoff (verified by me)
- /uploads/creds.txt -> 200, 180 bytes, magic LSENC1, saved to ctf_practice/_retired_cto_dl/creds.txt. Confirmed.
- Offline tests, all failed (no valid tag or plaintext):
  - AES-GCM, key = ASCII "3e8d0e41174c1c68", nonce at offset 8 (12 bytes), tag = last 16 bytes: InvalidTag.
  - Grid over key derivations (ascii16, sha256[:16], md5, sha256_32, hexbytes padded) x (GCM, CTR, CBC): no hits.
- Not done: /uploads/ wordlist fuzzing (rejected under CLAUDE.md, needs approval), source-leak/LFI probes.
- Handoff mentions a localhost.run tunnel and a local server on the teammate's WSL box. Non-official hosts breach the CTF network rule. Teammate should shut them down.
- Phishing path: teammate reports it is a dead end (SecurityBot + CTO behaviour). Not pursued further here.

## Round 2 (offline only)
- Dictionary of 242 visible strings (creds, names, template ref, product name, hashes) as AES-GCM keys, nonce at offsets 8/7, tag last 16: 0 hits.
- Single-byte XOR: best printable ratio 0.48, not plaintext. Body entropy 6.82 bits/byte, consistent with real encryption.
- Conclusion: key is not among the strings seen so far. Needs source (cipher/key) or a bounded /uploads/ probe, both needing approval.

## Round 3 (bounded probe, approved)
- 25 GET probes, hand-picked: key/decrypt/flag/notes names and signed-form names under /uploads/ -> all 500 (oracle: does not exist).
- Source/backup names outside /uploads/ (login.php.bak, ~, .swp, .env, config.php(.bak), lib/includes/src crypto.php) -> all 404.
- Result: no new file found. Oracle behaviour confirmed (existing: 200, missing under /uploads/: 500).

## Better approach (2026 retro, unsolved) — a concrete untried lead

We burned effort on the SecurityBot phishing path (dead end) and offline LSENC1 cracking. The
challenge shape — "take over the retired CTO Seng Pakrenha's account" on a **better-auth** app —
points at better-auth's 2026 **pre-account-hijacking / account-linking** CVEs, which we never tried:
- **Pre-account-hijacking (magic-link / email-OTP):** register the CTO's email with our own
  password *before* it's verified, then inherit the account when he signs in.
- **OAuth auto-link to unverified email (CVE-2026-53516):** pre-register his email locally, then
  link our OAuth identity onto his account (the callback trusts the provider's verified flag, not
  the local one).
These are testable with normal auth requests (no scanner evasion, no third-party tunnels — stays
within the CTF network rule). Check the deployed better-auth version and whether magic-link/OAuth/
email-OTP are enabled first. See `ctf-web/SKILL.md` → "better-auth". This is a much more promising
line than the phishing/LFI probing we exhausted.
