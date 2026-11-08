# Horsepower (picoCTF 2021, Binary Exploitation, Hard) — IN PROGRESS

Target: `nc chatelaine.cylabacademy.net 31967` (official instance, from the challenge page)
Files: `ctf_practice/horsepower/server.py`, `ctf_practice/horsepower/source.tar.gz` (V8 patch only, no d8 binary).
`ctf_practice/horsepower/Unconfirmed 499002.crdownload` is an incomplete Chrome download, not usable.

## Bug (from source/patch)
- `Array.prototype.setHorsepower(h)` (Torque `ArraySetHorsepower`) does `this.length = h`
  with no check against the backing store capacity. Gives out-of-bounds read/write on
  fast-element arrays.
- The patch also strips `read`, `load`, `os`, `Worker`, etc. from d8. Only `print`,
  `version`, `quit`, `Breakpoint` (int3) remain, so the flag needs shellcode.

## Confirmed on remote (V8 9.1.0, pointer compression ON)
- Interpreter OOB reads and writes to raw heap work (`a[k] = 1.5` for k past capacity lands in memory).
- Compressed slots: a[0] address = `(slot(10)-1)+8`, where slot 10 is a's elements field (`A0` in scratchpad common.js).
- Locating an object: holder `[X, S1, S2]` with Smi sentinels, scan window for S1,S2.
- JSTypedArray layout (off-heap, length 0x100): external_pointer raw 8 bytes at object+40.
- Overwriting ta1's external_pointer with ta2's makes ta1[i] alias ta2 (verified: 90 and 119).

## Not done yet
- addrOf(wasm exported function) returned a bogus object (dump shows canonical NaN words).
  Next: check the scan window / holder result, then follow JSFunction -> SharedFunctionInfo
  -> WasmExportedFunctionData -> instance.
- Need the wasm code address (instance jump table or body). Plan: give the wasm function a
  large body, overwrite it with shellcode via the typed array, call it. Shellcode should
  open/read/write the flag to fd 1 and exit_group(0). Flag path unknown (try /flag, /app/flag.txt, flag.txt).
- Unknown: whether wasm code memory is RWX in this build.

## Scratch
Probe scripts and the remote sender live in
`/tmp/claude-1000/-home-sira--claude-spares-spare-N0sDC1/62860656-b8f7-4e52-a81b-4ba59340466c/scratchpad/hp/`
(`remote.py <file.js>` sends a script to the official instance; `common.js` holds the helpers).

Flag: not found yet.
