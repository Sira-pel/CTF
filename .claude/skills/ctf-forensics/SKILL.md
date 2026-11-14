---
name: ctf-forensics
description: CTF forensics only: disk images, memory dumps, PCAPs, event logs, steganography, file carving. Use only when the evidence files are the challenge. Not for binaries to reverse or exploit, or cryptanalysis.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
  author: Lukasz Jagiello
---

# CTF Forensics & Blockchain

Quick reference for forensics CTF challenges. Each technique has a one-liner here; see supporting files for full details.

## Tool Availability Policy

Before installing anything below, check whether the tool/package already exists on this machine (`which <tool>`, `command -v <tool>`, `<tool> --version`, `pip show <pkg>`, etc.) and just use it if so. Only when something required is genuinely missing, tell the user which tool/package is missing and why the task needs it, then ask them to install it (or confirm before installing it yourself) — do not install new tools silently.

## Prerequisites

**Python packages (all platforms):**
```bash
pip install volatility3 Pillow numpy matplotlib scipy librosa scikit-learn opencv-python-headless pymongo impacket brotli exrex stegano heatshrink2
```

**Linux (apt):**
```bash
apt install binwalk foremost libimage-exiftool-perl tshark sleuthkit \
  ffmpeg steghide testdisk john pcapfix
```

**macOS (Homebrew):**
```bash
brew install binwalk exiftool wireshark sleuthkit ffmpeg \
  testdisk john-jumbo
```

**Ruby gems (all platforms):**
```bash
gem install zsteg
```

## Additional Resources

- [3d-printing.md](3d-printing.md) - 3D printing forensics (PrusaSlicer binary G-code, QOIF, heatshrink)
- [windows.md](windows.md) - Windows forensics (registry, SAM, event logs, recycle bin, NTFS alternate data streams, USN journal, PowerShell history, Defender MPLog, WMI persistence, Amcache)
- [network.md](network.md) - Network forensics basics (tcpdump, TLS/SSL keylog decryption, TLS master key extraction from coredump, Wireshark, PCAP, port scanning, SMB3 decryption, 5G/NR protocols, WordPress recon, credentials, USB HID steno, BCD encoding, HTTP file upload exfiltration, split archive reassembly via timestamp ordering)
- [network-advanced.md](network-advanced.md) - Advanced network forensics (packet interval timing encoding, NTLMv2 hash cracking, TCP flag covert channel, DNS last-byte steganography, DNS trailing byte binary encoding, multi-layer PCAP with XOR + ZIP and mDNS key, Brotli decompression bomb seam analysis, SMB RID recycling via LSARPC, Timeroasting MS-SNTP hash extraction, dnscat2 reassembly, RADIUS shared secret cracking, RC4 stream identification, ICMP payload byte rotation, ICMP ping time-delay covert channel)
- [peripheral-capture.md](peripheral-capture.md) - USB/HID/Bluetooth peripheral traffic reconstruction (USB HID mouse/pen drawing recovery, USB HID keyboard capture decoding, USB keyboard LED Morse code exfiltration, USB HID keyboard arrow key navigation tracking, Bluetooth RFCOMM packet reassembly)
- [disk-and-memory.md](disk-and-memory.md) - Core disk/memory forensics (Volatility, disk mounting/carving, VM/OVA/VMDK, VMware snapshots, GIMP raw memory dump visual inspection, coredumps, Windows KAPE triage, PowerShell ransomware, Android forensics, Docker container forensics, cloud storage forensics, BSON reconstruction, TrueCrypt/VeraCrypt mounting)
- [disk-advanced.md](disk-advanced.md) - Advanced disk and memory techniques (deleted partitions, ZFS forensics, GPT GUID encoding, VMDK sparse parsing, memory dump string carving, ransomware key recovery, WordPerfect macro XOR, minidump ISO 9660 recovery, APFS snapshot recovery, RAID 5 XOR recovery, HFS+ resource fork recovery, Kyoto Cabinet hash DB forensics, SQLite edit history reconstruction)
- [disk-recovery.md](disk-recovery.md) - Disk recovery and extraction patterns (LUKS master key recovery, PRNG timestamp seed brute-force, VBA macro binary recovery, FemtoZip decompression, XFS filesystem reconstruction, tar duplicate entry extraction, nested matryoshka filesystem extraction, anti-carving via null byte interleaving, BTRFS subvolume/snapshot recovery, FAT16 free space data recovery, FAT16 deleted file recovery via Sleuth Kit fls/icat, ext2 orphaned inode recovery via fsck, corrupted ZIP header repair)
- [steganography.md](steganography.md) - General steganography (binary border stego, PDF multi-layer stego, SVG keyframes, PNG reorder, file overlays, GIF frame diff Morse code, GZSteg + spammimic, spreadsheet frequency recovery, Kitty terminal graphics protocol decoding, ANSI escape sequence steganography, autostereogram solving, two-layer byte+line interleaving, multi-stream video container stego, progressive PNG layered XOR decryption, QR code reconstruction from curved reflection)
- [stego-image.md](stego-image.md) - Image-specific steganography (JPEG unused DQT table LSB, BMP bitplane QR extraction, image puzzle reassembly, F5 JPEG DCT ratio detection, PNG unused palette entry stego, QR code tile reconstruction, seed-based pixel permutation + multi-bitplane QR, JPEG thumbnail pixel-to-text mapping, conditional LSB with pixel filtering, JPEG slack space, nearest-neighbor interpolation stego, RGB parity steganography)
- [stego-advanced.md](stego-advanced.md) - Advanced steganography part 1: audio and signal techniques (FFT frequency domain, DTMF audio, SSTV+LSB, DotCode barcode, custom frequency dual-tone keypad, multi-track audio differential subtraction, cross-channel multi-bit LSB, audio FFT musical notes, audio metadata octal encoding, nested tar whitespace encoding, DeepSound audio stego with password cracking, audio waveform binary encoding, audio spectrogram hidden QR)
- [stego-advanced-2.md](stego-advanced-2.md) - Advanced steganography part 2: video, image transform, and format-specific techniques (video frame accumulation, reversed audio, video frame averaging, JPEG XL TOC permutation steganography, Arnold's Cat Map descrambling, high-resolution SSTV custom FM demodulation, MJPEG FFD9 trailing byte stego, EXIF zlib + Stegano pixel patterns, PDF xref covert channel, ANSI escape code stego, pixel-wise ECB deduplication)
- [linux-forensics.md](linux-forensics.md) - Linux/app forensics (log analysis, Docker image forensics, attack chains, browser credentials, Firefox history, TFTP, TLS weak RSA, USB audio, Git directory recovery, KeePass v4 cracking, Git reflog/fsck squash recovery, browser artifact analysis (Chrome/Chromium/Firefox history, cookies, downloads, local storage, session restore), corrupted git blob repair via byte brute-force, VBA macro Excel cell data to ELF binary extraction, Python in-memory source recovery via pyrasite)
- [signals-and-hardware.md](signals-and-hardware.md) - Hardware signal decoding with decode code (VGA frame parsing, HDMI TMDS symbol decode, DisplayPort 8b/10b + LFSR descrambler), Voyager Golden Record audio, Saleae Logic 2 UART decode, Flipper Zero .sub files, side-channel power analysis (DPA), keyboard acoustic side-channel, CD audio disc image steganography (CIRC de-interleaving + spiral rendering), caps-lock LED Morse code from video, Linux input_event keylogger dump parsing, serial UART from WAV audio, USB MIDI Launchpad grid reconstruction

---

## When to Pivot

- If you recover an encrypted blob and the hard part becomes RSA, AES, or lattice work, switch to `/ctf-crypto`.
- If the evidence really points to malware staging, beacon config extraction, or packed samples, switch to `/ctf-malware`.
- If the artifact is a web app backup or API dump and the remaining problem is application logic, switch to `/ctf-web`.
- If the forensic evidence is really an encoding puzzle, steganography trick, or esoteric format rather than true forensics, switch to `/ctf-misc`.
- If you need to trace infrastructure, attribute actors, or investigate public records from forensic findings, switch to `/ctf-osint`.
- If the recovered artifact is a compiled binary or firmware that needs disassembly and analysis, switch to `/ctf-reverse`.

## Quick Start Commands

```bash
# File analysis
file suspicious_file
exiftool suspicious_file     # Metadata
binwalk suspicious_file      # Embedded files
strings -n 8 suspicious_file
hexdump -C suspicious_file | head  # Check magic bytes

# Disk forensics
sudo mount -o loop,ro image.dd /mnt/evidence
fls -r image.dd              # List files
photorec image.dd            # Carve deleted files

# Memory forensics (Volatility 3)
vol -f memory.dmp windows.info
vol -f memory.dmp windows.pslist
vol -f memory.dmp windows.filescan
```

See [disk-and-memory.md](disk-and-memory.md) for full Volatility plugin reference, VM forensics, and coredump analysis.

## Detailed Sections

Technique-by-technique notes (the long tail) live in [details.md](details.md). Read it, or grep it for your keyword, once the quick start and the topic files above have not settled the challenge.
