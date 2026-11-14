"""Emit stone lists for each hidden-parameter / salt encoding."""
import hashlib
import json
from pathlib import Path

ROOT = Path("/home/sira/Documents/CTF/Lancang_Mekong_CTF_comp/solved/crypto_steal_beneath_the_seal")
d = json.loads((ROOT / "instance.json").read_text())
h = 1171995462696
A = int(d["anchor"])
MOD = int(d["silt_lock"]["modulus"])
salt_hex = d["silt_lock"]["salt"]
target = int(d["silt_lock"]["target"])
N = int(d["silt_lock"]["count"])


def minbe(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def stones(param: int, salt: bytes):
    pb = minbe(param)
    out = []
    for i in range(N):
        msg = pb + b"|silt-lock-stone-v2|" + salt + i.to_bytes(2, "big")
        dig = hashlib.sha256(msg).digest()
        out.append(int.from_bytes(dig, "big") % MOD)
    return out


def main():
    outdir = ROOT / "work"
    encs = []
    for name, p in [("h", h), ("s", A + h)]:
        for sname, salt in [("hex", bytes.fromhex(salt_hex)), ("ascii", salt_hex.encode())]:
            st = stones(p, salt)
            path = outdir / f"stones_{name}_{sname}.txt"
            path.write_text(str(target) + "\n" + "\n".join(map(str, st)) + "\n")
            encs.append(path.name)
            print(path.name, "wrote", N)
    print("MOD", MOD)


if __name__ == "__main__":
    main()
