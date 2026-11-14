# edge-appliance-specter (forensics)

Flag: `LMC{crimson_enclave_stage_premount_tunnel_beacon}`

## Evidence

- `appliance_edge.pcapng`: gateway `10.250.4.1` (`vpn-edge-gw01`) to resolver `10.250.0.2`, plus decoy NTP and fake TLS on `:443`.
- `firmware_triage.tar.gz`: boot logs, TPM2 event log, `apex-anchor`, `appliance-core`, SquashFS.

## Part 1 — enclave identity

`apex-anchor` replays PCR 14 from the TCG event log (SHA-256 extend, start at 32 zero bytes) and keeps the digest after the second extend. It XOR-decodes four profile names with key `5a a5 3c c3` and accepts the one where `SHA256(pcr2 || SHA256(name))` equals the logged final PCR.

That name is `crimson_enclave`. The other candidates (`emerald`, `sapphire`, `obsidian`) do not match. Boot log stage-3 PCR `eb81be42…f79e` matches.

## Part 2 — boot runtime stage

`/etc/init.d/appliance-core` starts the daemon with `--stage-hook=stage_premount`. That string is the HMAC key below; a different stage fails AES-GCM.

## Part 3 — beacon token

DNS labels under `gw-sync.infra-edge.net` are base32 frames:

- `aa 01 <seq>` + payload + CRC-16/CCITT-FALSE over everything except the last two bytes
- seq `0x95` has the final bit set (index `0x15`)
- duplicate seqs `03`, `07`, `0c` fail the CRC (one-byte corruption)

`appliance-core` derives the key as:

```
k1  = HMAC-SHA256(key="stage_premount", data="crimson_enclave")
key = HMAC-SHA256(key=k1, data="appliance-v2\\x01")
AES-256-GCM IV  = 9e4f2b1a8c3d7e6f0a5b2c4d
AAD             = vpn-edge-gw01
```

Plaintext is a JSON inventory. This host is `cluster_bravo` / `active_gateway` (also in `cluster.conf`), whose `beacon_token` is `tunnel_beacon`. The other tokens (`shadow_beacon`, `debug_beacon`) belong to standby and diagnostic nodes.

`status/updates/crl` DNS and the `:443` streams are cover traffic.
