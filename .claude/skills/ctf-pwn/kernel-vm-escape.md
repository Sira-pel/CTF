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
- Interpreter pwn (custom VM, Lua, SUBLEQ): treat VM memory as your heap; OOB index → interpreter struct / function table.

## Browser (V8 / SpiderMonkey)

- Read the `.diff`. Standard chain: bug → `addrOf`/`fakeObj` → arbitrary R/W in the heap cage → escape.
- V8 sandbox (2024+): in-cage R/W is not enough; target the trusted pointer table / code pointers outside the cage.
- Pin the exact d8 build (`git checkout` the commit in the handout) before writing offsets.

## Modern mitigations

- CET/IBT: returns/indirect branches may require `endbr64` landing pads — build ROP/JOP only to such targets.
- Shadow stack (if present) further constrains returns; SROP/sigreturn is one *possible* bypass, not the default for every "CET" challenge (SECCON selfcet: software `endbr64` check + partial overwrite + constrained ROP, no SROP).
- glibc ≥ 2.32 safe-linking and the no-hooks (≥ 2.34) FSOP/exit_funcs path: see the SKILL.md decision tree and Field lessons.
