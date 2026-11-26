# Exotic architectures, hidden logic, drivers, and big VMs

Open on demand when the target doesn't look like a normal x86/ARM binary. Companion to [platforms-hardware.md](platforms-hardware.md) and [unicorn-emulation.md](unicorn-emulation.md).

## Exotic architecture checklist

1. `file`, `readelf -h` → `e_machine`. Unknown → search "<arch> ghidra processor" / emulator.
2. Run it: `qemu-<arch>` user mode, or the console emulator (MAME, mGBA, Pokemon-Mini emu) with its debugger.
3. Use the emulator's breakpoints on input reads; dump RAM after the check.

## Logic hidden outside normal code

- DWARF: `readelf --debug-dump=frames,info bin`; DWARF expression ops can be a full VM.
- Exception/unwind tables (`.eh_frame`, `.pdata`) sized far beyond the code: the unwind bytecode is the program — decode the CFI records as opcodes instead of reversing functions.
- printf VM: custom `register_printf_function` / `%n`-heavy format tables = opcodes.
- Shaders (WebGL/GLSL): copy shader source from the browser (Spector.js), port to numpy, solve.
- Regex / automaton checkers: convert to DFA, then BFS for an accepting input.
- NN/model file as checker: extract weights → Z3 bitvectors over each layer (`f_i(x) = target[i]`); never train.
- Linear/matrix flag checkers: pad/rotate blocks, then solve the matrix per block in the modular ring the checker uses (often mod the alphabet size).
- pcap + VM binary: timing gaps between packets can be the bytecode (pick the threshold from the gap histogram); reconstruct the bits, then disassemble.
- seccomp/BPF checker: dump the filter first (`seccomp-tools dump` or `bpftool`) instead of reading the disassembly.

## Drivers and kernel modules

- Windows `.sys`: `DriverEntry` → `IRP_MJ_DEVICE_CONTROL` handler → switch on IOCTL code.
- Linux `.ko` (also Rust `.ko`): `file_operations.unlocked_ioctl` → per-cmd handlers.

## Big custom VMs

- Write a disassembler first (opcode → mnemonic), then a lifter to Python/z3. Don't single-step thousands of handlers.
- Multithreaded or self-checking VMs: dump state at a sync point, or emulate with Unicorn to skip anti-tamper.
- SIMD/vectorized VMs (SSE/AVX lanes): emulate with Unicorn or lift each lane independently.
- Unusual bases (ternary CPUs): write the custom disassembler/emulator before any solving; binary assumptions fail.

## Compiled-language noise

- Rust: strings aren't NUL-terminated (ptr,len pairs); `core::panicking` marks bounds checks; demangle with `rustfilt` and use panic strings as oracles.
- Rust proc-macros: the macro expansion is the obfuscation — `cargo expand` or compile per-char samples to recover the encoding, then decode greedily.
- Nim: `main` → `NimMain` → `NimMainInner` → `NimMainModule` (user top-level code); demangle `<ident>__<module>_u<id>` names with ESET's nimfilt; seq/string headers precede data.
- Recognise the algorithm (Perrin, Fibonacci, CRC, TEA) before trying to solve it.
