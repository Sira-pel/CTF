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

Tools are installed manually as needed; each category skill lists its own prerequisites and checks before installing (see its Tool Availability Policy). Model choice and stop-loss rules: [difficulty-routing.md](difficulty-routing.md).

Deep-dive research (two mixed-difficulty-challenge studies: reports, per-challenge CSV with recognition signals, source links) lives in `research/` at the repo root — start at `research/README.md` if you open it. On-demand reference only, don't auto-load it.

## Hypothesis First (before acting on any finding)

1. **List 2-3 hypotheses** for what the bug, check, or vulnerability is, each with its evidence.
2. **Rank them** by likelihood and cost to test.
3. **Test each** with one cheap, read-only check first (`strings`, `checksec`, a breakpoint, a small input, one request). Escalate to fuzzing, exploit work, or full decompilation only after a cheap test supports a hypothesis.

Follow the CTF rules in the project's `CLAUDE.md`.

**Hard rule:** never attack the CTF platform/scoreboard/infrastructure — or other teams or the venue — to find answers; only interact with challenge targets as intended. Heavy scanning, bulk fuzzing (nmap, sqlmap, ffuf, gobuster, `ctf-web/scripts/async_fuzz.py`), and online brute force against challenge hosts follow the event's own rules — ask if unsure. Offline cracking and internet use (writeup search, dogbolt.org, webhook.site, libc.rip) are fine. Ask before sudo, installs, or running unknown binaries; never run malware samples on the host.

## Hard-pattern triage (10s)

| If you see… | Do this first |
|---|---|
| Huge `.rela` / tiny `.text` | `readelf -rW -s` → reloc VM; do not start in main |
| 3-int bytecode / "subleq" / ELVM | OISC: try I/O matrix oracle before full lift |
| HLT / nested exceptions / RUNTIME_FUNCTION | Dump unwind / function-table callbacks offline |
| Custom VM + `nc` | RE opcodes, then look for OOB into interpreter state |
| Full RELRO + libc ≥ 2.34 | FSOP / exit_funcs / ROP — never `__free_hook` (removed) |
| Seccomp | `seccomp-tools dump`; ORW via raw `syscall` gadgets (libc `open` may be `openat`) |
| Write of a fixed buffer you don't control | Overwrite the next printed string / code ptr with that buffer |
| Node `fs.*(req…)` | Object/URL duck-type + encoding mismatch vs WAF |
| Flask+PHP / two parsers | HPP: first-wins vs last-wins |
| Proxy adds a query flag | Flood past `qs` `parameterLimit` (default 1000) |
| AES-GCM repeated IV | Forbidden attack → recover H, forge tag |
| Pickle w/o REDUCE/NEWOBJ | BUILD → `__setstate__` |
| AST bans `Call` | Decorator or `raise E` with dunder (`Exception.__getitem__`) |
| LLM "don't reveal flag" | Side-channel verify / confuse gate model |
| Pcap + memory dump | SSLKEYLOG / CS key extract before guessing crypto |
| `run.sh` + `qemu-system` + `bzImage`/`.ko` | Kernel pwn → `/ctf-pwn` kernel path (`kernel-vm-escape.md`) |
| QEMU launched with custom `-device` | Device escape: reverse MMIO/PIO handlers in the QEMU binary |
| Patched `d8`/`js` shell + `.diff` | Browser pwn: read the diff; goal = addrOf/fakeObj → AAR/AAW |
| Unknown `e_machine` (Hexagon, TILE-Gx, SM83…) | Find emulator/qemu-user + Ghidra processor plugin before reading bytes |
| Big `.debug_*`/DWARF, tiny code | Logic may live in DWARF expressions → `readelf --debug-dump` |
| `.sys`/`.ko` as the "checker" | Find the ioctl dispatch, then the input path into it |
| WebGL/shader source in a "rev" | Logic is in the shader; port GLSL to Python and solve |
| Rust/Nim/Go binary | Rename runtime noise first; find user `main`, then the comparison |
| Admin bot + strict CSP | Client-side chain → `/ctf-web` `client-side-chains.md` |

Event flag: `LMC{...}`. Notes: `notes/<challenge>.md`.

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

Invoke `/ctf-writeup` after solving. Mid-event it writes team-only notes to `notes/<challenge>.md`; never share or publish a writeup until the event ends.

## Flags

This event's flag format is `LMC{...}`. Other CTFs may use `flag{...}`, `CTF{...}`, or a prefix from the description. If several flag-like strings appear, treat them as candidates, prefer the one tied to the intended artifact, and check uniqueness across the corpus. Report the source file.

```bash
grep -rniE '(lmc|flag|ctf)\{' .
strings output.bin | grep -iE '\{.*\}'
```

## Challenge

$ARGUMENTS
