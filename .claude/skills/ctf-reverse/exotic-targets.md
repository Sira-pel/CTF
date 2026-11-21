# Exotic architectures, hidden logic, drivers, and big VMs

Open on demand when the target doesn't look like a normal x86/ARM binary. Companion to [platforms-hardware.md](platforms-hardware.md) and [unicorn-emulation.md](unicorn-emulation.md).

## Exotic architecture checklist

1. `file`, `readelf -h` → `e_machine`. Unknown → search "<arch> ghidra processor" / emulator.
2. Run it: `qemu-<arch>` user mode, or the console emulator (MAME, mGBA, Pokemon-Mini emu) with its debugger.
3. Use the emulator's breakpoints on input reads; dump RAM after the check.

## Logic hidden outside normal code

- DWARF: `readelf --debug-dump=frames,info bin`; DWARF expression ops can be a full VM.
- printf VM: custom `register_printf_function` / `%n`-heavy format tables = opcodes.
- DVD / media VM: the disc's navigation commands are the program.
- Shaders (WebGL/GLSL): copy shader source from the browser (Spector.js), port to numpy, solve.
- Regex / automaton checkers: convert to DFA, then BFS for an accepting input.
- Markov / string-rewrite machines: lift the rule table, simulate in Python.

## Drivers and kernel modules

- Windows `.sys`: `DriverEntry` → `IRP_MJ_DEVICE_CONTROL` handler → switch on IOCTL code.
- Linux `.ko` (also Rust `.ko`): `file_operations.unlocked_ioctl` → per-cmd handlers.

## Big custom VMs

- Write a disassembler first (opcode → mnemonic), then a lifter to Python/z3. Don't single-step thousands of handlers.
- Multithreaded or self-checking VMs: dump state at a sync point, or emulate with Unicorn to skip anti-tamper.

## Compiled-language noise

- Rust: strings aren't NUL-terminated (ptr,len pairs); `core::panicking` marks bounds checks.
- Nim: `NimMain` → `<module>Init000`; seq/string headers precede data.
- Recognise the algorithm (Perrin, Fibonacci, CRC, TEA) before trying to solve it.
