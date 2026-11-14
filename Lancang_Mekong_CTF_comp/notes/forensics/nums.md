# Num (Forensics, 150) — SOLVED

**Flag:** `LMC{THAT_TIME_WAS_SO_FUN_WHEN_IT_DIDN'T_HAVE_AI:))}`

## Path
1. `num.zip` contains `num.docx`. Visible text is `Num yum yum yum yum` plus a photo of num ansom chrouk.
2. Unreferenced `word/media/wh76fzgap2gf1.jpeg` has JPEG comment `kuorhC_mosnA_muN`. Reversed, that is the password `Num_Ansom_Chrouk`.
3. `word/media/relele.zip` is WinZip AES-256. It holds `relele.txt`, base64 written backwards. Reversed and decoded, it is a 1500×1125 PNG of a floating village.
4. PNG chunk `laLa` is only the byte `X` (a marker). RGB LSBs are a 4-byte length (`0x178f`) plus a gzip stream. Gunzip yields a 32.1 s, 22050 Hz, 16-bit mono WAV.
5. The WAV is 600 Hz on-off keying. Dits are ~58 ms, dahs ~178 ms. Morse decodes to `THAT_TIME_WAS_SO_FUN_WHEN_IT_DIDN'T_HAVE_AI:))`.
6. Wrap that string: `LMC{THAT_TIME_WAS_SO_FUN_WHEN_IT_DIDN'T_HAVE_AI:))}`.

## Better approach (2026 retro)

Six nested layers solved by hand. Faster next time: `binwalk -eM` for the carve/compression
layers, `zsteg -a` for the PNG LSB (the gzip-in-LSB would surface directly), `stegseek` for any
steghide passphrase, and a spectrogram (`sox in.wav -n spectrogram`) to confirm the OOK Morse
before hand-decoding dit/dah durations. The reversed-base64 and JPEG-comment password still need
a human eye, but the tooling removes most of the manual carving. See `ctf-forensics/SKILL.md`.
