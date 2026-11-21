---
name: ctf-misc
description: Fallback for CTF challenges that fit no other category: encoding puzzles, pyjails, bash jails, RF/SDR, esoteric languages, QR/audio puzzles. Use only after ctf-crypto, ctf-reverse and ctf-pwn clearly do not apply; never for binaries, memory corruption or real cryptanalysis.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task Skill
metadata:
  user-invocable: "false"
  author: Lukasz Jagiello
---

# CTF Miscellaneous

Quick reference for miscellaneous CTF challenges. Each technique has a one-liner here; see supporting files for full details.

## Tool Availability Policy

Before installing anything below, check whether the tool/package already exists on this machine (`which <tool>`, `command -v <tool>`, `<tool> --version`, `pip show <pkg>`, etc.) and just use it if so. Only when something required is genuinely missing, tell the user which tool/package is missing and why the task needs it, then ask them to install it (or confirm before installing it yourself) — do not install new tools silently.

## Prerequisites

**Python packages (all platforms):**
```bash
pip install "pwntools==4.15.0" "segno==1.6.6" z3-solver Pillow numpy requests dnslib
```

**Linux (apt):**
```bash
apt install libzbar0 qrencode ffmpeg
```

**macOS (Homebrew):**
```bash
brew install ffmpeg qrencode
```

**Manual install:**
- SageMath — Linux: `apt install sagemath`, macOS: `brew install --cask sage`

## Additional Resources

- [pyjails.md](pyjails.md) - Python jail/sandbox escape techniques, quine context detection, restricted character repunit decomposition, func_globals module chain traversal, restricted charset number generation, class attribute persistence, f-string config injection via stored eval
- [bashjails.md](bashjails.md) - Bash jail/restricted shell escape techniques, HISTFILE file read trick, bash -v verbose mode, ctypes.sh direct C library calls
- [encodings.md](encodings.md) - Encodings, QR codes, esolangs, UTF-16 tricks, BCD encoding, multi-layer auto-decoding, indexed directory QR reassembly, multi-stage URL encoding chains
- [encodings-advanced.md](encodings-advanced.md) - Verilog/HDL, Gray code cyclic encoding, RTF custom tag extraction, SMS PDU decoding, multi-encoding sequential solvers, UTF-9, pixel binary encoding, hexadecimal Sudoku + QR assembly, TOPKEK, MaxiCode
- [audio.md](audio.md) - Audio steganography and signal analysis: Morse code extraction from audio channels with auto-detection, spectrogram analysis, SSTV decoding, amplitude envelope timing classification
- [rf-sdr.md](rf-sdr.md) - RF/SDR/IQ signal processing (QAM-16, carrier recovery, timing sync)
- [dns.md](dns.md) - DNS exploitation (ECS spoofing, NSEC walking, IXFR, rebinding, tunneling)
- [games-and-vms.md](games-and-vms.md) - WASM patching, Roblox place file reversing, PyInstaller, marshal analysis, Python env RCE, Z3 (including boolean logic gate network SAT solving), K8s RBAC, floating-point precision exploitation, custom assembly language sandbox escape via Python MRO chain
- [games-and-vms-2.md](games-and-vms-2.md) - Cookie checkpoint game brute-forcing, Flask cookie game state leakage, WebSocket game manipulation, server time-only validation bypass, De Bruijn sequence, Brainfuck instrumentation, WASM linear memory manipulation
- [games-and-vms-3.md](games-and-vms-3.md) - memfd_create packed binaries, multi-phase crypto games with HMAC commitment-reveal and GF(256) Nim, emulator ROM-switching state preservation, Python marshal code injection, Benford's Law bypass, parallel connection oracle relay, nonogram solver pipelines, 100 prisoners problem, C code jail escape via emoji identifiers, BuildKit daemon build secret exploitation, Docker container escape, Levenshtein distance oracle attack, taint analysis bypass via type coercion, shredded document pixel-edge reassembly
- [games-and-vms-4.md](games-and-vms-4.md) - Part 4 (2018-era): XSLT as Turing-complete VM, JavaScript MAX_SAFE_INTEGER successor equality, binary search oracle in comparison-only DSL, blind SQLi via script-engine timeout error, OEIS sequence lookup automation, QR code reassembly from format-string constraints, matrix exponentiation for Fibonacci recurrence, Tribonacci for frog-jump counting, Selenium + Tesseract dynamic CAPTCHA, Brainfuck→Piet multi-layer polyglot, bytebeat synth code recognition
- [linux-privesc.md](linux-privesc.md) - Sudo wildcard parameter injection (fnmatch), crafted pcap for sudoers.d, monit confcheck process injection, Apache -d override, backup cronjob SUID, PostgreSQL COPY TO PROGRAM RCE, PostgreSQL backup credential extraction, NFS share exploitation, SSH Unix socket tunneling, PaperCut Print Deploy privesc, Squid proxy pivoting, Zabbix admin password reset via MySQL, WinSSHTerm credential decryption
- [ctfd-navigation.md](ctfd-navigation.md) - CTFd platform API navigation without browser: detection, token auth, challenge listing, file download, flag submission, scoreboard, hints, notifications, Python client class

---

## When to Pivot

- If the puzzle is actually centered on cryptography or number theory, switch to `/ctf-crypto`.
- If the challenge is a real binary exploit instead of a jail, toy VM, or encoding problem, switch to `/ctf-pwn` or `/ctf-reverse`.
- If the input is mostly files, images, audio, or packet captures that need recovery work first, switch to `/ctf-forensics`.
- For ML/AI techniques (model attacks, adversarial examples, LLM jailbreaking), see `/ctf-ai-ml`.
- If the NodeJS sandbox uses **vm2** (`npm ls vm2`), check for **CVE-2023-37466** via `Promise[@@species]` with `nesting:true` — the exception handler escapes the context; see [node-and-prototype.md](../ctf-web/node-and-prototype.md) for JS sandbox escape chains. In misc challenges with bundled JS, always run `npm ls vm2` to detect vulnerable vm2 before trying other escapes.

## Quick Start Commands

```bash
# File identification
file mystery_file
xxd mystery_file | head -5
python3 -c "import magic; print(magic.from_file('mystery_file'))"

# Encoding detection
python3 -c "import base64; print(base64.b64decode('<data>'))"
echo '<data>' | base64 -d
echo '<hex>' | xxd -r -p

# QR code
zbarimg qr.png
python3 -c "from pyzbar.pyzbar import decode; from PIL import Image; print(decode(Image.open('qr.png')))"

# Z3 constraint solving
python3 -c "from z3 import *; x=BitVec('x',32); s=Solver(); s.add(x^0xdead==0xbeef); s.check(); print(s.model())"

# Python jail test
python3 -c "__import__('os').system('id')"
```

## Modern jail patterns

- AST bans `Call`: decorator escape, or `class E(Exception): __getitem__ = os.system` then `raise E` / `except E as e: e["/bin/sh"]` — calls code without `ast.Call`. See [pyjails.md](pyjails.md).
- Restricted pickle (no REDUCE/INST/OBJ/NEWOBJ): use **BUILD** to rebind `__setstate__`, grabbing callables via GLOBAL from `__main__`/pickle internals — no REDUCE needed. See [pyjails.md](pyjails.md).
- JSFuck with broken `Array.toString`: rebuild chars via `Number.prototype.toString(radix)`; prefer dynamic `import("fs")` when `require` is gone.

## Detailed Sections

Technique-by-technique notes (the long tail) live in [details.md](details.md). Read it, or grep it for your keyword, once the quick start and the topic files above have not settled the challenge.
