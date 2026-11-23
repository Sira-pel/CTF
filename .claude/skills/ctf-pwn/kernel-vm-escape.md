# Kernel, VM-escape, and browser (V8) quick recipes

Open on demand for hard pwn targets. Companion to [kernel.md](kernel.md) (deep kernel material) and [kernel-techniques.md](kernel-techniques.md) (cross-cache, PTE, userfaultfd).

## Kernel quick path

- Unpack: `mkdir r && cd r && zcat ../initramfs.cpio.gz | cpio -idm`; `extract-vmlinux bzImage > vmlinux` (or `vmlinux-to-elf`).
- Debug: add `-s -S` to qemu, `gdb vmlinux -ex 'target remote :1234'`; set `nokaslr` locally only.
- Primitive ladder: UAF/overflow → spray a known object (seq_operations, msg_msg, pipe_buffer, tty_struct) → leak → AAW → `modprobe_path` / `core_pattern` / cred overwrite.
- Race windows: `userfaultfd` (old kernels) or FUSE / `MADV_DONTNEED` when uffd is unprivileged-disabled.
- Panic-reboot (`oops=panic panic=1`) lets you retry a flaky leak — locally only.
- eBPF: read the verifier patch; build a program where verifier range ≠ runtime value → OOB map access.

## Device / VM escape

- QEMU custom device: find `*_mmio_read/_write` in the qemu binary; index/size fields checked on one path but not the other.
- QEMU + virtio device source shipped: audit the device callbacks before the guest heap — a UAF in a device-side heap → corrupt the virtqueue → host escape. Guest-only heap work is a dead end here.
- Custom hypervisor with a guest ioctl/port-I/O device: OUT/ioctl traps into hypervisor handlers — audit them (they may copy attacker data into host JIT RWX memory).
- Interpreter pwn (custom VM, Lua, SUBLEQ): treat VM memory as your heap; OOB index → interpreter struct / function table.
- Custom JIT VM: grep every pc/ip update for missing bounds; an unchecked interpreter pc can overlap BSS and rewrite later opcodes at runtime (GET-style opcodes become self-modifying).

## Nested KVM (L2 → L1)

- Diff the L0 KVM binary against a stock build (BinDiff) for planted OOB in `handle_vmread`/`handle_vmwrite` handlers.
- Backdoored vmread/vmwrite give OOB access via x86 debug registers; walk the L1 `task_struct` chain from `init_task` once you can read L1 memory.

## HDL / soft CPUs

- Verilog CPUs: privilege checks keyed on the **fetch** PC can fire before the **retire** PC — stall (NOPs) so fetch crosses the privilege boundary while the check still sees the old PC.

## Windows kernel

- EPROCESS field redirect via counters/stats structs: bitflip/overwrite a stats field (e.g., DiskCounters) to overlap Token → enable SeDebugPrivilege → open a parent SYSTEM process. Leak via `NtQuerySystemInformation`. Needs a Windows analysis VM (WinDbg / FLARE-VM), not the Linux host.

## Firmware / secure boot

- ESP32 secure boot (ESP-IDF): a bootloader that writes segments **before** verifying them is bypassable — inject a segment load-addr past the verify branch. `esptool.py image_info` first; XOR-obfuscated segments may need retries.

## Browser (V8 / SpiderMonkey)

- Read the `.diff`. Standard chain: bug → `addrOf`/`fakeObj` → arbitrary R/W in the heap cage → escape.
- V8 sandbox (2024+): in-cage R/W is not enough; target the trusted pointer table / code pointers outside the cage.
- Pin the exact d8 build (`git checkout` the commit in the handout) before writing offsets.
- Revenge/"SBX round 2" challenges usually patch last cycle's escape — re-diff instead of reusing old paths.
- Turboshaft IR bug class: load elimination across GC safepoints (a WordPtr stack-arg load cast to tagged ignores a GC move); you need a GC inside the window.

## Modern mitigations

- CET/IBT: returns/indirect branches may require `endbr64` landing pads — build ROP/JOP only to such targets.
- Shadow stack (if present) further constrains returns; SROP/sigreturn is one *possible* bypass, not the default for every "CET" challenge (SECCON selfcet: software `endbr64` check + partial overwrite + constrained ROP, no SROP).
- glibc ≥ 2.32 safe-linking and the no-hooks (≥ 2.34) FSOP/exit_funcs path: see the SKILL.md decision tree and Field lessons.
