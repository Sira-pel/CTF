# Hard200 report — 100 NEW hard CTF challenges

## Counts by category
- pwn: 38
- rev: 19
- web: 13
- misc: 11
- crypto: 10
- forensics: 3
- malware: 3
- blockchain: 2
- hardware: 1

Total: 100. Target mix was ~60 RE+pwn; actual pwn+rev = 57.

## Hardness evidence
- Rows with strong solve-count / finishers / high points evidence: **96/100**
- Prefer 2023–2026; excluded all hard100 + hard28 names.

## Tool frequency (this study)
- Ghidra: 30
- pwntools: 25
- gdb: 17
- Python: 16
- Sage: 11
- Burp: 10
- browser: 6
- QEMU: 4
- Z3: 4
- d8: 2
- binwalk: 2
- Volatility: 2
- tshark: 2
- torch: 2
- x64dbg: 2
- Foundry: 2
- llvm-objdump: 1
- Bindiff: 1
- syzkaller: 1
- Frida: 1
- QEMU/KVM: 1
- Verilator: 1
- riscv: 1
- WinDbg: 1
- Windows kernel: 1
- C: 1
- esptool: 1
- bpftool: 1
- numpy: 1
- rustfilt: 1
- Unicorn: 1
- rustc: 1
- readelf: 1
- Wireshark: 1
- devtools: 1
- Node: 1
- Rails: 1
- fpylll: 1
- 7z: 1
- zbar: 1
- LLM: 1
- FLOSS: 1
- Solidity: 1
- KiCad: 1

## Trends
- Nested virt (KVM L2→L1, virtio→QEMU, custom hypervisors) keeps dominating hard pwn.
- V8 moves into Turboshaft IR bugs and sandbox-revenge patches.
- Windows kernel EPROCESS redirects and ESP32 secure-boot image tricks appear in top-tier events.
- RE: exception/.eh_frame VMs, Rust proc-macros, ternary CPUs, NN-as-checker + Z3.
- Misc jails: C-level audit-hook bypass via interpreter UAF; pickle BUILD bypass.
- AI/ML: adversarial JPEG through DiffJPEG; adversarial audio vs Whisper; LLM WAF bypass.
- Malware: Flare-On 11 finals remain the gold standard multi-stage RE.

## Top 10 insights for Pel's skills
1. Byte-swap only? Corrupt top-chunk size so sysmalloc fenceposts and frees old top (boogie-woogie).
2. Guest OUT/ioctl into hypervisor JIT RWX (dicer-visor) — always audit hypercall handlers.
3. HDL CPU privilege using fetch PC ≠ retire PC (C(OOOO)RCPU).
4. Windows: redirect DiskCounters over Token for SeDebugPrivilege (Process Flipper).
5. V8 Turboshaft load-elim across GC safepoints (mirage).
6. ESP-IDF secure boot writes segments before verify (ESPecially secure boot).
7. .eh_frame / unwind tables as hidden VMs (thiefcat).
8. Pickle BUILD writes __dict__ past restricted setattr (Just Another Pickle Jail).
9. CPython audit hooks: need interpreter memory corruption (IRS / #91153).
10. Adversarial ML: match train-time JPEG+crop pipeline with DiffJPEG+PGD (what-a-jpeg-is).

## Proposed skill changes (token-lean)
- ctf-pwn: add triage rows for hypervisor port-I/O, nested KVM, virtio device audit, Windows EPROCESS redirect, ESP secure-boot segment inject, byte-swap→top-chunk, patched-libc DF recipes.
- ctf-reverse: .eh_frame VM signal; Rust proc-macro expansion; ternary/SIMD VM; NN weights→Z3; TCP-timing bytecode.
- ctf-web: SXG, Sanitizer API, safest-note isolation, Rails strong-params.
- ctf-misc: audit-hook UAF; pickle BUILD; zip+7z symlink polyglot.
- ctf-ai-ml: DiffJPEG PGD recipe; Whisper adversarial; LLM WAF encodings.
- ctf-malware: point to Flare-On 11 CATBERT/fullspeed/clearlyfake as practice ladder.
- Efficiency: prefer recognition→action one-liners over prose; keep SOURCES.md as sole citation file.

## New tools to install (Ubuntu)
- `pipx install pwntools ROPgadget one_gadget`
- `sudo apt install qemu-system-x86 qemu-user-static gdb-multiarch`
- `# Windows kernel: use FLARE-VM / WinDbg in analysis VM (not on Kali)`
- `pip install angr unicorn capstone keystone-engine z3-solver`
- `sudo apt install seccomp-tools || gem install seccomp-tools`
- `# V8: build d8 from challenge-pinned commit`
- `pip install torch torchvision  # adversarial ML`
- `# DiffJPEG: pip install DiffJPEG or vendor from challenge`
- `sudo apt install wireshark-common tshark binwalk`
- `cargo install rustfilt  # Rust demangling`
