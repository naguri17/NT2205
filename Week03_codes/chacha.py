#!/usr/bin/env python3
"""
Step-through teaching version of Poly1305 and ChaCha20-Poly1305 AEAD.
Prints mathematical formulas and pauses for student input.
Educational use only — not for production.
"""

import struct

P130 = (1 << 130) - 5

def pause():
    input("Press Enter to continue...\n")

# ---------- Poly1305 ----------
def _clamp_r(r_bytes: bytes) -> int:
    r = int.from_bytes(r_bytes, "little")
    clamp_mask = 0x0ffffffc0ffffffc0ffffffc0fffffff
    print(f"Clamp r:")
    print(f"    r = r & {hex(clamp_mask)}")
    pause()
    return r & clamp_mask

def poly1305_mac_teach(msg: bytes, key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes")
    r_bytes, s_bytes = key[:16], key[16:]
    r = _clamp_r(r_bytes)
    s = int.from_bytes(s_bytes, "little")

    print(f"Poly1305 parameters:")
    print(f"    r (after clamp) = {r}")
    print(f"    s = {s}")
    pause()

    acc = 0
    offset = 0
    while offset < len(msg):
        block = msg[offset:offset+16]
        offset += len(block)
        n = int.from_bytes(block + b'\x01', "little")
        print("Process block:")
        print(f"    n = int(block)||1 = {n}")
        print(f"    Formula: acc = (acc + n) * r mod (2^130 - 5)")
        acc = (acc + n) % P130
        acc = (acc * r) % P130
        print(f"    New acc = {acc}")
        pause()

    print("Final tag computation:")
    print("    tag = (acc + s) mod 2^128")
    tag_int = (acc + s) % (1 << 128)
    print(f"    tag = {tag_int}")
    pause()
    return tag_int.to_bytes(16, "little")

# ---------- ChaCha20 ----------
def _rotl32(x, n): return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

def _quarter_round_teach(a, b, c, d):
    print("Quarter Round:")
    print(f"    a = (a + b) mod 2^32; d = (d XOR a) <<< 16")
    print(f"    c = (c + d) mod 2^32; b = (b XOR c) <<< 12")
    print(f"    a = (a + b) mod 2^32; d = (d XOR a) <<< 8")
    print(f"    c = (c + d) mod 2^32; b = (b XOR c) <<< 7")
    pause()
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = _rotl32(d, 16)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = _rotl32(b, 12)
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = _rotl32(d, 8)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = _rotl32(b, 7)
    return a, b, c, d

def chacha20_block_teach(key32: bytes, counter: int, nonce12: bytes) -> bytes:
    def u32(b): return struct.unpack("<I", b)[0]
    state = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        u32(key32[0:4]), u32(key32[4:8]), u32(key32[8:12]), u32(key32[12:16]),
        u32(key32[16:20]), u32(key32[20:24]), u32(key32[24:28]), u32(key32[28:32]),
        counter, u32(nonce12[0:4]), u32(nonce12[4:8]), u32(nonce12[8:12])
    ]
    print("ChaCha20 initial state = constants || key || counter || nonce")
    pause()

    x = state.copy()
    for i in range(10):
        print(f"Double Round {i+1}:")
        pause()
        # Column rounds
        x[0],x[4],x[8],x[12]   = _quarter_round_teach(x[0],x[4],x[8],x[12])
        x[1],x[5],x[9],x[13]   = _quarter_round_teach(x[1],x[5],x[9],x[13])
        x[2],x[6],x[10],x[14]  = _quarter_round_teach(x[2],x[6],x[10],x[14])
        x[3],x[7],x[11],x[15]  = _quarter_round_teach(x[3],x[7],x[11],x[15])
        # Diagonal rounds
        x[0],x[5],x[10],x[15]  = _quarter_round_teach(x[0],x[5],x[10],x[15])
        x[1],x[6],x[11],x[12]  = _quarter_round_teach(x[1],x[6],x[11],x[12])
        x[2],x[7],x[8],x[13]   = _quarter_round_teach(x[2],x[7],x[8],x[13])
        x[3],x[4],x[9],x[14]   = _quarter_round_teach(x[3],x[4],x[9],x[14])
    out_words = [(x[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return b"".join(struct.pack("<I", w) for w in out_words)

def chacha20_encrypt_teach(key32, nonce12, plaintext, initial_counter=1):
    out = bytearray()
    pos, counter = 0, initial_counter
    while pos < len(plaintext):
        block = chacha20_block_teach(key32, counter, nonce12)
        chunk = plaintext[pos:pos+64]
        print(f"Encryption formula: C = P ⊕ keystream_block (counter={counter})")
        pause()
        for i, b in enumerate(chunk):
            out.append(b ^ block[i])
        pos += len(chunk)
        counter += 1
    return bytes(out)

# ---------- AEAD ----------
def _pad16(data): return b"" if len(data)%16==0 else b"\x00"*(16-(len(data)%16))

def aead_chacha20_poly1305_encrypt_teach(key32, nonce12, aad, plaintext):
    block0 = chacha20_block_teach(key32, 0, nonce12)
    poly_key = block0[:32]
    print("Poly1305 key derivation:")
    print("    PolyKey = ChaCha20(key, counter=0, nonce)[:32]")
    pause()

    ciphertext = chacha20_encrypt_teach(key32, nonce12, plaintext, 1)

    mac_data = aad + _pad16(aad) + ciphertext + _pad16(ciphertext)
    mac_data += len(aad).to_bytes(8,"little")
    mac_data += len(ciphertext).to_bytes(8,"little")
    print("Tag input composition:")
    print("    TagInput = aad || pad16(aad) || ciphertext || pad16(ciphertext) || len(aad) || len(ciphertext)")
    pause()
    tag = poly1305_mac_teach(mac_data, poly_key)
    return ciphertext, tag

# ---------- Example run ----------
if __name__ == "__main__":
    key = bytes(range(32))
    nonce = bytes(range(12))
    aad = b"header"
    pt = b"Poly1305 + ChaCha20 AEAD teaching demo."

    ct, tag = aead_chacha20_poly1305_encrypt_teach(key, nonce, aad, pt)
    print("Final Results:")
    print("    Ciphertext =", ct.hex())
    print("    Tag =", tag.hex())
