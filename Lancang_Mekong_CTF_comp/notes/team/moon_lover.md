# Moon Lover (Team_Work 030, 523)

`LMC{G3chwi!thy0u%^&}` is the real `moon` entry password (header hash matches the XML, sample entries decrypt to `Password` / `12345`). It was submitted and marked incorrect.

The mistake in the challenge text is the KeePass master-password leak. That password is what the memory remnants recover, and it is what actually opens the database:

`LMC{GechIsn0tFailinLove@@@}` opens the KDBX (stream-start check passes) but was rejected by the scoreboard. It is the master password, not the flag.

The in-memory XML has only Sample Entry, Sample Entry #2, and `moon`. No other secret is in that database. `JumpOverTheMoon` sits in a malware string table (`LoadAssemblyFromEncryptedUrl`), so it is not the secret.

Remaining lead: Edge history has a locked Pastebin, `https://pastebin.com/efZdTNa0`, title `hzxj - Pastebin.com`, plus a "Locked Paste" / "Unlock The Paste" page. The paste body is not in the dump. A login redirect `return_url=%2FefZdTNa0` is present. Do not fetch pastebin until approved.

Archive password from the brief: `!ZE3RFFpmg#w8u26`. File is a 5GB Windows raw memory dump (`moon_memdump1.raw`). `LMC{flag_fake}` in Edge is a decoy search.

## What was hidden

KeePass 2 database `Documents\work\Hc3gSiv2.kdbx` (KDBX 3.1, AES-KDF, 60000 rounds). Entry titled `moon` (username `NA`). Password field is Salsa20-protected in the XML that was still in memory.

Sample entries decrypted to the stock values `Password` and `12345`, which checks the keystream order. The moon value `b+oUFciOvty0Is7f5HeK` decrypts to `G3chwi!thy0u%^&`.

## The mistake

KeePass left the master password in process memory as UTF-16 strings of U+25CF bullets plus the next typed character (CVE-2023-32784). Every character except the first is recoverable. Reconstructed and checked against the header’s stream-start bytes:

`GechIsn0tFailinLove@@@`

That master password opens the database. The submitted secret is the moon entry, not the master password.

## Better approach (2026 retro)

The master-password recovery was done by hand via CVE-2023-32784. Automate with
**`keepass-password-dumper`** (vdohney) — point it at the 5 GB raw dump, `pagefile.sys`, or
`hiberfil.sys`; it recovers all-but-the-first-character directly, and mister-turtle's port emits a
John-the-Ripper mask to fill the gap. But note the *actual* blocker here isn't recovery technique —
both the `moon` entry password and the KDBX master password were rejected by the scoreboard. The
unsolved lead is the **locked Pastebin** (`pastebin.com/efZdTNa0`) in Edge history; the flag is
likely its body, not anything in the KeePass DB. Drive the 5 GB dump with **volatility3** (Edge
process memory / cached web content, `windows.filescan`+`dumpfiles`) to try to recover the paste
body offline before any approved network fetch. See `ctf-forensics/SKILL.md` → "Memory dumps".
