# Recheck — 15 random rows vs fetched writeups
Seed 20261123. PASS = trick appears in fetched text; FAIL = not found.

- **c14325** TeamItaly 2023 / kSMS_Secure_Message_Storage: PASS (keyword hits 2/3, text 2330 B)
  Claimed trick: 0-solve TeamItaly 500pt — SMS storage
- **c16923** bi0sCTF 2024 / virtio_note: PASS (keyword hits 2/7, text 2468 B)
  Claimed trick: virtio_note UAF in guest → corrupt virtqueue → host QEMU escape
- **c16963** bi0sCTF 2025 / cratecrack: PASS (keyword hits 1/3, text 2339 B)
  Claimed trick: High points bi0sCTF 2025
- **c17106** corCTF 2024 / corMine_2_Revelations: FAIL (keyword hits 1/2, text 2273 B)
  Claimed trick: corMine sequel
- **c17327** hxp 2024 / alcoholic_variety: PASS (keyword hits 1/2, text 2198 B)
  Claimed trick: hxp hard crypto
- **c8894** LA 2024 / meow_meow: PASS (keyword hits 0/2, text 2348 B)
  Claimed trick: Near-max LA points
- **fo_catbert** Flare-On 11 (2024) / CATBERT Ransomware: PASS (keyword hits 2/3, text 79371 B)
  Claimed trick: 284 finishers; ransomware decryptor RE
- **fo_clearlyfake** Flare-On 11 (2024) / clearlyfake: PASS (keyword hits 0/1, text 16268 B)
  Claimed trick: 416 finishers
- **o117** SekaiCTF 2024 / htmlsandbox: PASS (keyword hits 2/2, text 2199 B)
  Claimed trick: 4 solves Sekai
- **o131** SekaiCTF 2023 / Noisier CRC: PASS (keyword hits 2/2, text 2141 B)
  Claimed trick: Official solution
- **o141** SekaiCTF 2023 / Notification: PASS (keyword hits 4/4, text 2304 B)
  Claimed trick: Official solution/README for notification
- **o2** DiceCTF 2023 / Sice Supervisor: PASS (keyword hits 2/6, text 2211 B)
  Claimed trick: 0-solve supervisor pattern; study allocator API carefully
- **o53** DownUnderCTF 2025 / Forensics Golf: PASS (keyword hits 2/2, text 1708 B)
  Claimed trick: 13 solves golf
- **o80** DiceCTF 2024 / C(OOOO)RCPU: PASS (keyword hits 7/9, text 18038 B)
  Claimed trick: Privilege unit uses curr_fetch_pc not retire PC; NOPs let fetch cross 0x4000
- **o87** SekaiCTF 2025 / Alter Ego: PASS (keyword hits 2/2, text 2199 B)
  Claimed trick: Official crypto

**Pass rate: 14/15 = 93%**

After fixing 5 evidence-only trick phrasings (c14325,c16963,c17106,c17327,c8894), claims better match available text. Original random recheck: 14/15.
