# CTF research summaries — all three hard-challenge studies

One-page summary of the three studies in this folder (228 challenges total). Detailed per-challenge data:
[hard100-report.md](hard100-report.md) (100 challenges, 2021–2026) ·
[hard28-report.md](hard28-report.md) (28 challenges, 2022–2024) ·
[hard200-report.md](hard200-report.md) (100 NEW hard challenges, difficulty-verified: 96/100 strong evidence, recheck 14/15 — [hard200-recheck.md](hard200-recheck.md)) ·
[hard100-challenges.csv](hard100-challenges.csv) + [hard200-challenges.csv](hard200-challenges.csv) (per-challenge trick/tools/signal/pitfall/takeaway) ·
[SOURCES.md](SOURCES.md) (every writeup link from all three studies, with difficulty/hardness evidence).

**Mixed difficulty:** of the first 128, roughly **55–70 are truly hard**; ~40–55 are medium or easier, and ≥5 easy/beginner rows slipped into the "hard-100" set (ctf42's Hard label is a heuristic — e.g. SECCON babycmp: labelled Hard, actually a 176-solve XOR warmup). The **hard200** set is difficulty-verified (96/100 strong solve-count/points evidence). Prefer solve counts / author notes when picking practice targets.

These are reference material, not skill content: open them on demand. Writeup lookup follows the project rules (past-event writeups fine; current-event lookup needs asking first).

## Tools by category (count of the 100 hard challenges whose solve used them)

| Category | Tools (count) |
|---|---|
| pwn (30) | gdb/pwndbg 31, pwntools 19, qemu-system 9, d8/js shell 3, ROPgadget 2, clang 2, bpftool 1 |
| rev (24) | Ghidra 18, Python 7, z3 4, qemu-user 3, IDA/WinDbg 2, emulators (MAME, mGBA) 3, pyelftools 1, Unicorn 1, angr 1 |
| web (15) | Burp 15, real browser + DevTools 5, ysoserial/Java 2, php_filter_chain_generator 1 |
| crypto (12) | Sage 7, Python 6, fpylll 4, randcrack 2, z3, sympy, pycryptodome |
| forensics (8) | Wireshark 4, tshark 2, python-evtx/chainsaw, impacket-secretsdump, hashcat/john, gpp-decrypt, olevba, sox/numpy |
| misc/AI (11) | Python 8, pickletools/dis, browser 5 |

Across all 100 (hard100): gdb 31, Python 25, Ghidra 19, pwntools 19, Burp 15, browser 12, QEMU 11, Sage 7, z3 5, fpylll 4, Wireshark 4.

**hard200 study tool frequency:** Ghidra 30, pwntools 25, gdb 17, Python 16, Sage 11, Burp 10, browser 6, QEMU 4, Z3 4, d8 2, binwalk 2, Volatility 2, tshark 2, torch 2, x64dbg 2, Foundry 2; singles include llvm-objdump, Bindiff, syzkaller, Frida, Verilator, esptool, bpftool, rustfilt, Unicorn, FLOSS, KiCad, WinDbg. Notable trends: nested virt (KVM L2→L1, virtio→QEMU, custom hypervisors) dominates hard pwn; V8 moves to Turboshaft IR bugs; Windows-kernel EPROCESS redirects and ESP32 secure-boot tricks at top-tier events; DiffJPEG/Whisper adversarial ML; C-level audit-hook jailbreaks.

## Techniques per category (count in the 100; hand-bucketed from CSV tags — see [hard100-challenges.csv](hard100-challenges.csv))

- **pwn (30):** kernel incl. eBPF/race/cross-cache 9, VM/emulator escape or interpreter pwn ~5, browser engine 3, glibc heap ~5–8 (definition-dependent), non-glibc runtimes (Rust, Lua, musl, OCaml, Nim) ~4.
- **rev (24):** custom VM ~8, exotic architecture ~5, driver/kernel-module 3, "logic elsewhere" (shader/media/DWARF) 5.
- **web (15):** XSS/CSP/client-side chains ~5, parser/smuggling/type confusion 6, deserialization 2.
- **crypto (12):** lattices (CVP/HNP/LLL) 5, PRNG prediction ~5, oracle attacks 3, isogeny 1.
- **forensics (8):** Windows artifacts ~4, network decrypt 3.
- **misc/AI (11):** pickle/jail 5, LLM 5.

Pack coverage across the 100 (CSV-derived): **covered 16 / partial 64 / gap 20**.

## Recurring recognition signals → technique

| Signal in the handout | Likely technique |
|---|---|
| `run.sh` + `bzImage` + `.ko` | Kernel heap/race → spray (msg_msg / pipe_buffer / seq_ops) → modprobe_path / cred |
| Verifier patch / BPF syscall allowed | eBPF verifier range mismatch → OOB map R/W |
| `qemu-system` with custom `-device` | Device MMIO bug → host escape (reverse the QEMU binary) |
| `d8` + `.diff` | V8 addrOf/fakeObj; 2024+ also needs a sandbox escape |
| Bytecode blob + dispatch loop + `nc` | Custom VM: disassemble, then OOB into interpreter state |
| CET/IBT enabled (`endbr64` everywhere) | endbr64-gated ROP/JOP; check the CET flavor (software endbr check ≠ shadow stack; SROP only sometimes applies) |
| glibc ≥ 2.32 heap | safe-linking: leak heap, `(pos>>12)^ptr`; ≥ 2.34 no hooks → TLS dtors / FSOP |
| Links musl / is Rust / Lua / OCaml | Allocator- or runtime-specific: unchecked index, tag confusion, fake objects |
| Odd `e_machine` / ROM file | Emulator + Ghidra processor first |
| `.sys`/`.ko` as checker | IOCTL dispatch → input path |
| WebGL shaders / DVD image / DWARF-heavy ELF | Logic hidden in non-CPU code: extract and port to Python |
| Admin bot + strict CSP | bfcache, service worker, header-too-large, DOM clobbering, mXSS |
| Two servers / proxy in front | Smuggling, Content-Length mismatch, response splitting, HPP |
| Java endpoint (RMI/Hessian) | Deserialization; JDK-only gadget chains |
| ECDSA + odd nonce source | HNP / related-nonce lattice |
| Shamir/LWE with too few equations | CVP / embedding |
| `Math.random` / Python `random` | Predict state (z3 xorshift128+, MT19937 untemper) |
| `.evtx`, SAM/SYSTEM, Groups.xml | chainsaw/evtx_dump, secretsdump, gpp-decrypt |
| Encrypted pcap + provided/recovered keys or dump | SSLKEYLOG → tshark |
| `addaudithook`, code objects, pickle scanner | Jail via parser differential / CodeType / memo |
| LLM with secret | Prompt leak in another language/format; boundary spoof; tool abuse |

## Trends 2021 → 2026 (CTFtime tags, 734 writeups; 2025–26 column is a hint, not a measurement)

- **pwn:** rop 8/7/1, UAF 7/7/2, heap 4/5/1, shellcode 6/2/0, kernel 2/0/1 — classic glibc heap fading; hard points now come from kernel, VM escape, and V8.
- **rev:** custom VM 1/4/3 — now the main hard-RE pattern. Rust steady (3/3/2), z3 up (4/7), angr down (2/0).
- **web:** xss 8/19/1, csp-bypass 3/10, sqli 3/6, prototype pollution 6/3/1 — hard web is mostly client-side chains.
- **crypto:** rsa 19/8/3 (falling), lattice 9/8 (steady) — the one crypto skill that keeps paying off. isogeny 1/3/1, zero-knowledge 0/1/1.
- **misc:** pickle 0/3/1; LLM/prompt-injection 0/1/2 — from none to common in 2025.

## Recommended laptop installs (Ubuntu — confirm before running; skills gate installs via their Tool Availability Policy)

```bash
# pwn / kernel
sudo apt install -y qemu-system-x86 qemu-user-static gdb-multiarch patchelf cpio
pipx install ropgadget && sudo gem install one_gadget seccomp-tools
pipx install git+https://github.com/marin-m/vmlinux-to-elf   # vmlinux from bzImage
git clone https://github.com/niklasb/libc-database ~/tools/libc-database
# crypto
sudo apt install -y python3-fpylll        # LLL/BKZ/CVP in Python
# Sage: easiest is docker:  docker pull sagemath/sagemath   (or: conda/mamba install -c conda-forge sage)
pip install --user randcrack
# forensics
sudo apt install -y tshark hashcat pngcheck sox
pipx install volatility3 && pipx install oletools && pipx install impacket && pip install --user python-evtx
sudo gem install zsteg
# stegseek: .deb from https://github.com/RickdeJager/stegseek/releases
pipx install name-that-hash
# hard200 additions
pip install angr unicorn capstone keystone-engine z3-solver   # RE/emulation
cargo install rustfilt          # Rust demangling
pip install torch torchvision DiffJPEG   # adversarial ML (DiffJPEG: or vendor from the challenge)
# seccomp BPF dump: seccomp-tools (above) or bpftool (apt linux-tools-common)
# V8: build d8 from the challenge-pinned commit (never a distro d8)
# Windows kernel/malware: FLARE-VM + WinDbg inside a disposable Windows analysis VM — not a Linux install
```

Note: this repo has no `install_ctf_tools.sh` (references were removed as broken; tools are installed manually per the skills' prerequisites). This list is the install reference.

Priority if time is short: qemu-system-x86, patchelf, ROPgadget, one_gadget, seccomp-tools, libc-database (RE/Pwn first), then Sage (docker) + fpylll, then tshark + hashcat.

## Practice queue

### hard-100 pass — 14 with public files, easiest first (RE/Pwn heavy)

*(SECCON 2022 babycmp was dropped: it's an easy XOR warmup — "Welcome to SECCON 2022", ~176 solves — not a hard angr challenge; ctf42's Hard label is wrong there. Optional angr demo at most.)*

| # | Challenge | Diff (evidence) | Why | Files |
|---|---|---|---|---|
| 1 | UIUCTF 2022 odd_shell (pwn) | medium | Restricted-byte shellcode | github.com/sigpwny/UIUCTF-2022-Public |
| 2 | SECCON 2023 jumpout (rev) | easy–med (~154 solves) | Jump-table obfuscation + xor | github.com/SECCON/SECCON2023_online_CTF |
| 3 | SECCON 2021 kasu_bof (pwn) | medium | ret2dlresolve with no leak | github.com/SECCON/SECCON2021_online_CTF |
| 4 | SECCON 2022 eguite (rev) | easy (author: relatively easy Rust rev) | Rust reversing + constraint cleanup | SECCON2022_online_CTF |
| 5 | SECCON 2023 xuyao (rev) | medium | Pointer-struct obfuscation; clean decomp then invert xor chain (no z3) | SECCON2023_online_CTF |
| 6 | DiceCTF 2024 baby-talk (pwn) | hard | Off-by-null → House of Einherjar → tcache | github.com/dicegang/dicectf-quals-2024-challenges |
| 7 | PlaidCTF 2021 Plaidflix (pwn) | hard/insane | UAF + safe-linking | github.com/sajjadium/ctf-archives/tree/main/ctfs/PlaidCTF/2021/pwn/Plaidflix |
| 8 | SECCON 2023 selfcet (pwn) | hard | Software CET (`endbr64` gate): partial overwrite + constrained ROP (not SROP) | SECCON2023_online_CTF |
| 9 | corCTF 2021 vmquack (rev) | unverified | Write your first full VM disassembler | github.com/Crusaders-of-Rust/corCTF-2021-public-challenge-archive |
| 10 | 0CTF 2022 ezvm (pwn) | unverified | Same VM skill turned into an exploit | github.com/sajjadium/ctf-archives/tree/main/ctfs/0CTF/2022/pwn/ezvm |
| 11 | SECCON 2023 DataStore1 (pwn) | hard | Heap type confusion + feng shui | SECCON2023_online_CTF |
| 12 | TSG 2021 lkgit (pwn) | hard (unverified) | First kernel race (userfaultfd) | github.com/tsg-ut/tsgctf2021 |
| 13 | HITCON 2022 kernel / Wall Rose 2023 (pwn) | hard | UAF → modprobe_path; cross-cache | perfectblue writeup + HITCON repos |
| 14 | SECCON 2022 babypf (pwn) | hard/insane | eBPF verifier bug (stretch goal) | SECCON2022_online_CTF |

### hard-28 pass — 10 from public archives, beginner → harder (RE/Pwn order)

| # | Challenge | Diff (report label) | Why | Files |
|---|---|---|---|---|
| 1 | DiceCTF 2023 bop | medium | Stack overflow + seccomp ORW (raw syscalls) | github.com/dicegang/dicectf-2023-challenges/tree/main/pwn/bop |
| 2 | Google CTF 2023 write-flag-where | medium | `/proc/self/mem` write of flag | google-ctf 2023 quals (writeup: cryptocat.me blog) |
| 3 | UIUCTF 2023 vmwhere1 | medium | Small VM | github.com/sigpwny/UIUCTF-2023-Public |
| 4 | corCTF 2022 simplewaf | medium | Node URL object | github.com/Crusaders-of-Rust/corCTF-2022-public-challenge-archive/tree/master/web/simplewaf |
| 5 | SECCON 2022 skipinx | easy–med | qs limit | github.com/arkark/my-ctf-challenges (web/skipinx) |
| 6 | Google CTF 2023 UNDER-CONSTRUCTION | medium | HPP | github.com/google/google-ctf (2023 quals web) |
| 7 | Google CTF 2022 Treebox | medium | AST jail | google-ctf 2022 |
| 8 | SECCON 2022 babyfile | hard | FSOP/obstack | github.com/ret2school/ctf/tree/master/2022/seccon/pwn/babyfile |
| 9 | HITCON 2023 LessEQualmore | med–hard | SUBLEQ RE | github.com/bronson113/My_CTF_Challenges |
| 10 | Google CTF 2022 eldar | hard | Reloc VM (stretch) | google-ctf 2022 + Midās writeup |

Always-on: [pwn.college](https://pwn.college/program-security/) Program Security hard ROP / RE modules.

## Caveats

- Tool counts come from tools each writeup uses; always-present tools (pwntools in pwn) are undercounted.
- CTFtime/ctf42 tags are community-entered and sparse — read trends as direction only. ctf42's Hard/Insane label is a heuristic (solve-rank + agent + event weight) and mislabeled warmups (babycmp); prefer solve counts / author tags.
- "Covered" in the CSV means the skills have a usable path; "Partial" = mentioned, no quick recipe; "Gap" = missing.
- Technique counts above are hand-bucketed from CSV tags; recount from [hard100-challenges.csv](hard100-challenges.csv) if precision matters.
