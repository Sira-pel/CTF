# Wrap Battle (PWN, 323) — SOLVED

**Flag:** `LMC{the_manifest_arrived_unwrapped}`

## Setup
- `Lancang_Mekong_CTF_comp/solved/pwn_wrap_battle/wrap_battle`, stripped PIE ELF.
- Remote: `nc 47.131.225.172 19406`, minimal HTTP/1.1.
- Routes: `POST /append`, `POST /correct`, `GET /snapshot`, `POST /consume`, `GET /status`.
- Eight cargo views. Body buffer is 0x100 bytes at BSS `0x6058`; view 0 metadata begins at `0x6158`.
- Each connection has a secret. The log callback at `0x6050` is stored as `(PIE+0x1249) ^ secret`. `GET /status` returns that secret in the last 8 bytes of its 64-byte body.
- An unreferenced loader at `0x1355` opens `flag`, then `/run/challenge/flag`, and writes it to stdout.

## Bug
`Content-Length` and `Transfer-Encoding: chunked` disagree. A normal body cannot exceed 0x100, but a chunked body uses `Content-Length` (up to 0x1000) as its copy limit and writes into the 0x100 buffer. The overflow lands on the view metadata.

## Solve
1. `GET /status` and read the secret at body offset 0x38.
2. `POST /append` one byte so view 0 points at the arena (`PIE+0x5040`).
3. Chunked `POST /append` of 0x104 bytes overwrites view 0's length with 0x1010. `GET /snapshot` then reads through the arena to the saved arena pointer at offset 0x1008, giving the PIE base. The snapshot stops at the callback, so it cannot leak the encoded pointer directly.
4. Another chunked append sets view 0's pointer to the callback and its length to 8.
5. `POST /correct` writes `(PIE+0x1355) ^ secret` through that pointer.
6. The next `POST /append` invokes the loader after its HTTP response. The flag follows on the same socket.

## Notes
- Confirmed locally first: the redirected loader printed a temporary `flag` file created in `/tmp`.
- The Python pipe buffer hid that local write; the remote socket read returned it directly.

## Better approach (2026 retro)

This is a classic **CL.TE request-smuggling desync** (Content-Length vs Transfer-Encoding
chunked disagreement) — naming it that points straight at the methodology: a `smuggler.py`-style
differential probe finds the parser disagreement without reversing the buffer sizes by hand.
The overflow-onto-view-metadata + XOR-encoded-callback overwrite was the right follow-through.
