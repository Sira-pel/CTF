---
name: solve-challenge
description: Entry point for CTF challenges when the category is unclear: quick triage, then routes to ctf-crypto, ctf-reverse or ctf-pwn first, or another ctf-* skill. Skip it when the category is obvious.
license: MIT
compatibility: Requires filesystem-based agent with bash, Python 3, and internet access.
allowed-tools: Bash Read Write Edit Glob Grep Task Skill
metadata:
  user-invocable: "true"
  argument-hint: "[category] [challenge-file-or-url]"
  author: Lukasz Jagiello
---

# CTF Challenge Solver

Goal: solve the challenge and find the flag.

Tools: `bash scripts/install_ctf_tools.sh all` pre-installs everything. Otherwise each category skill lists its own prerequisites; install as you go. Model choice and stop-loss rules: [difficulty-routing.md](difficulty-routing.md).

Follow the CTF rules in the project's `CLAUDE.md`, including its hypothesis-first rule (the single source for it).

## Workflow

### Step 0: Platform

If a URL is given, check for CTFd (`curl -s "$CTF_URL/api/v1/" | head -5`). If CTFd, ask the user for an API token (CTFd Settings > Access Tokens) and invoke `/ctf-misc` for `ctfd-navigation.md`. If the platform is not CTFd or is JS-only, drive it with Playwright MCP and prefer a native API when one exists.

### Step 1: Recon

`file *`, `strings`, `xxd | head`, `binwalk`, `checksec` on binaries. Fetch any linked URLs first. Try `nc` on remote services. Read descriptions, filenames and comments for hints.

### Step 2: Categorize

- **File type:** `.pcap/.pcapng/.evtx/.raw/.dd/.E01` → forensics. `.elf/.exe/.so/.dll` or extensionless binary → reverse, or pwn if a remote service exists. `.py/.sage` or numeric `.txt` → crypto. `.apk/.wasm/.pyc` → reverse. `.safetensors/.pt/.pth/.bin/.onnx` → ai-ml. HTML/JS/PHP or a URL → web. Images/audio/PDF with no content → forensics (stego).
- **Keywords:** overflow/ROP/shellcode/heap → pwn. RSA/AES/cipher/lattice/GCM → crypto. XSS/SQL/JWT/SSRF → web. disk/memory/pcap/side-channel → forensics. find/locate/who/where → osint. obfuscated/C2/beacon → malware. adversarial/LoRA/embedding → ai-ml. jail/sandbox/encoding/game → misc.
- **Service:** interactive crash on long input → pwn. HTTP → web. math puzzles over netcat → crypto. restricted shell or eval → misc.

### Step 3: Invoke the category skill

| Category | Skill | Category | Skill |
|---|---|---|---|
| Web | `/ctf-web` | Malware | `/ctf-malware` |
| Pwn | `/ctf-pwn` | AI/ML | `/ctf-ai-ml` |
| Crypto | `/ctf-crypto` | Misc | `/ctf-misc` |
| Reverse | `/ctf-reverse` | OSINT | `/ctf-osint` |
| Forensics | `/ctf-forensics` | | |

### Step 4: Pivot when stuck

Re-check the category, try a second category skill (many challenges span two), look for hidden files, alternate ports, headers, source comments and metadata, and check for a simpler path (default creds, known CVE, logic bug). Also check edge cases: off-by-one, races, overflow, encoding mismatches.

Process lessons from our past solves (time-boxing, decoy flags, validating tools, remote-service handling): [lessons.md](lessons.md).

Common cross-category combinations: forensics+crypto (encrypted data in a capture or image), web+reverse (WASM or obfuscated JS), web+crypto (JWT or custom MAC), reverse+pwn (understand the binary first), forensics+OSINT (recover data, then trace it), misc+crypto (jail escape that needs crypto primitives).

### Step 5: Write-up

Invoke `/ctf-writeup` after solving.

## Flags

This event's flag format is `LMC{...}`. Other CTFs may use `flag{...}`, `CTF{...}`, or a prefix from the description. If several flag-like strings appear, treat them as candidates, prefer the one tied to the intended artifact, and check uniqueness across the corpus. Report the source file.

```bash
grep -rniE '(lmc|flag|ctf)\{' .
strings output.bin | grep -iE '\{.*\}'
```

## Challenge

$ARGUMENTS
