#!/usr/bin/env python3
"""
Teaching version: ChaCha20 + Poly1305 (ChaCha20-Poly1305 AEAD)
- Prints algorithm overviews first (optional)
- Prints 16-word ChaCha20 state with labels
- Prints quarter-round formulas with explicit mapping a/b/c/d -> state words
- Step-through mode: pauses after each printed formula; disable with --auto
Educational only — NOT for production.
"""

import struct
import hmac
import argparse
import sys

# Toggle: step-by-step pauses if True
STEP_BY_STEP = True

def pause():
    if STEP_BY_STEP:
        input("Press Enter to continue...\n")

# -----------------------
# Algorithm overview printers
# -----------------------
def poly1305_overview():
    print("[Poly1305] Algorithm overview:")
    print("  Input: 32-byte one-time key (r || s), message M")
    print("  Clamp: r = r & 0x0ffffffc0ffffffc0ffffffc0fffffff")
    print("  MAC computation:")
    print("    acc = 0")
    print("    For each 16-byte block m_i (last block may be shorter):")
    print("       n = int_le(m_i) + (1 << (8*len(m_i)))  # i.e. append 0x01 byte in little-endian")
    print("       acc = (acc + n) * r  (mod 2^130 - 5)")
    print("    tag = (acc + s) mod 2^128")
    pause()

def chacha20_overview():
    print("[ChaCha20] Algorithm overview (RFC-style):")
    print("  Input: 256-bit key, 32-bit block counter, 96-bit nonce")
    print("  Initial 4x4 state (words, little-endian):")
    print("    [ c0,  c1,  c2,  c3 ]")
    print("    [ k0,  k1,  k2,  k3 ]")
    print("    [ k4,  k5,  k6,  k7 ]")
    print("    [ ctr, n0,  n1,  n2 ]")
    print("  Process:")
    print("    Repeat 10 times (each is a double-round → 20 rounds total):")
    print("       4 column quarter rounds, then 4 diagonal quarter rounds")
    print("  QuarterRound(a,b,c,d) formulas (in order):")
    print("    a = (a + b) mod 2^32; d = ROTL(d XOR a, 16)")
    print("    c = (c + d) mod 2^32; b = ROTL(b XOR c, 12)")
    print("    a = (a + b) mod 2^32; d = ROTL(d XOR a, 8)")
    print("    c = (c + d) mod 2^32; b = ROTL(b XOR c, 7)")
    pause()

# -----------------------
# Poly1305 implementation (verbose)
# -----------------------
P130 = (1 << 130) - 5

def _clamp_r_verbose(r_bytes: bytes) -> int:
    r_before = int.from_bytes(r_bytes, "little")
    clamp_mask = 0x0ffffffc0ffffffc0ffffffc0fffffff
    print(f"[Poly1305] r (before clamp) = {r_before}")
    print(f"[Poly1305] Clamp formula: r = r & {hex(clamp_mask)}")
    pause()
    r_after = r_before & clamp_mask
    print(f"[Poly1305] r (after clamp) = {r_after}")
    pause()
    return r_after

def poly1305_mac_verbose(msg: bytes, key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes")
    r_bytes, s_bytes = key[:16], key[16:]
    r = _clamp_r_verbose(r_bytes)
    s = int.from_bytes(s_bytes, "little")
    print(f"[Poly1305] s = {s}")
    pause()

    acc = 0
    offset = 0
    block_index = 0
    while offset < len(msg):
        block = msg[offset:offset+16]
        offset += len(block)
        # n = int_le(block) + (1 << (8*len(block)))  (equivalent to int(block + b'\x01'))
        n = int.from_bytes(block + b'\x01', "little")
        print(f"[Poly1305] Block #{block_index}: len={len(block)}")
        print(f"    n = int_le(block) || 0x01 = {n}")
        print("    Formula: acc = (acc + n) * r mod (2^130 - 5)")
        acc = (acc + n) % P130
        acc = (acc * r) % P130
        print(f"    New acc = {acc}")
        pause()
        block_index += 1

    tag_int = (acc + s) % (1 << 128)
    print(f"[Poly1305] Final formula: tag = (acc + s) mod 2^128")
    print(f"[Poly1305] Final tag (int) = {tag_int}")
    pause()
    return tag_int.to_bytes(16, "little")

def poly1305_verify_verbose(tag: bytes, msg: bytes, key: bytes) -> bool:
    mac = poly1305_mac_verbose(msg, key)
    ok = hmac.compare_digest(mac, tag)
    print("[Poly1305] Verification result:", ok)
    pause()
    return ok

# -----------------------
# ChaCha20 block & helper printing
# -----------------------
def _rotl32(x, n): return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

def _print_state_matrix(x, labels):
    # x: 16-word state; labels: 16 labels for each word
    print("[ChaCha20] Current 4x4 state (rows):")
    for r in range(4):
        row_words = []
        for c in range(4):
            idx = r*4 + c
            row_words.append(f"{labels[idx]}={x[idx]:#010x}")
        print("   " + " | ".join(row_words))
    pause()

def _quarter_round_verbose(a, b, c, d, labels):
    # labels: [label_a, label_b, label_c, label_d]
    print("[ChaCha20] QuarterRound on:")
    print(f"    a := {labels[0]} = {a:#010x}")
    print(f"    b := {labels[1]} = {b:#010x}")
    print(f"    c := {labels[2]} = {c:#010x}")
    print(f"    d := {labels[3]} = {d:#010x}")
    print("    Formulas (apply in order):")
    print("      a = (a + b) mod 2^32; d = ROTL(d XOR a, 16)")
    print("      c = (c + d) mod 2^32; b = ROTL(b XOR c, 12)")
    print("      a = (a + b) mod 2^32; d = ROTL(d XOR a, 8)")
    print("      c = (c + d) mod 2^32; b = ROTL(b XOR c, 7)")
    pause()

    a = (a + b) & 0xffffffff; d ^= a; d = _rotl32(d, 16)
    c = (c + d) & 0xffffffff; b ^= c; b = _rotl32(b, 12)
    a = (a + b) & 0xffffffff; d ^= a; d = _rotl32(d, 8)
    c = (c + d) & 0xffffffff; b ^= c; b = _rotl32(b, 7)

    print("[ChaCha20] QuarterRound result:")
    print(f"    a = {a:#010x}, b = {b:#010x}, c = {c:#010x}, d = {d:#010x}")
    pause()
    return a, b, c, d

def chacha20_block_verbose(key32: bytes, counter: int, nonce12: bytes) -> bytes:
    if len(key32) != 32 or len(nonce12) != 12:
        raise ValueError("key must be 32 bytes and nonce 12 bytes")

    def u32(b): return struct.unpack("<I", b)[0]

    state = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,   # constants
        u32(key32[0:4]), u32(key32[4:8]), u32(key32[8:12]), u32(key32[12:16]),
        u32(key32[16:20]), u32(key32[20:24]), u32(key32[24:28]), u32(key32[28:32]),
        counter,                                           # block counter (32-bit)
        u32(nonce12[0:4]), u32(nonce12[4:8]), u32(nonce12[8:12])  # nonce words
    ]

    labels = [
        "c0", "c1", "c2", "c3",
        "k0", "k1", "k2", "k3",
        "k4", "k5", "k6", "k7",
        "ctr", "n0", "n1", "n2"
    ]

    print("[ChaCha20] Initial 16-word state layout (labels and words):")
    _print_state_matrix(state, labels)

    x = state.copy()
    # 10 double-rounds -> 20 rounds
    for dr in range(10):
        print(f"[ChaCha20] --- Double round {dr+1} ---")
        pause()
        # Column rounds: (0,4,8,12), (1,5,9,13), (2,6,10,14), (3,7,11,15)
        # We pass labels corresponding to each index so students see mapping
        x0,x4,x8,x12 = x[0],x[4],x[8],x[12]
        x[0],x[4],x[8],x[12] = _quarter_round_verbose(
            x0,x4,x8,x12,
            labels=[labels[0], labels[4], labels[8], labels[12]]
        )
        _print_state_matrix(x, labels)

        x1,x5,x9,x13 = x[1],x[5],x[9],x[13]
        x[1],x[5],x[9],x[13] = _quarter_round_verbose(
            x1,x5,x9,x13,
            labels=[labels[1], labels[5], labels[9], labels[13]]
        )
        _print_state_matrix(x, labels)

        x2,x6,x10,x14 = x[2],x[6],x[10],x[14]
        x[2],x[6],x[10],x[14] = _quarter_round_verbose(
            x2,x6,x10,x14,
            labels=[labels[2], labels[6], labels[10], labels[14]]
        )
        _print_state_matrix(x, labels)

        x3,x7,x11,x15 = x[3],x[7],x[11],x[15]
        x[3],x[7],x[11],x[15] = _quarter_round_verbose(
            x3,x7,x11,x15,
            labels=[labels[3], labels[7], labels[11], labels[15]]
        )
        _print_state_matrix(x, labels)

        # Diagonal rounds: (0,5,10,15), (1,6,11,12), (2,7,8,13), (3,4,9,14)
        a,b,c,d = x[0],x[5],x[10],x[15]
        x[0],x[5],x[10],x[15] = _quarter_round_verbose(
            a,b,c,d,
            labels=[labels[0], labels[5], labels[10], labels[15]]
        )
        _print_state_matrix(x, labels)

        a,b,c,d = x[1],x[6],x[11],x[12]
        x[1],x[6],x[11],x[12] = _quarter_round_verbose(
            a,b,c,d,
            labels=[labels[1], labels[6], labels[11], labels[12]]
        )
        _print_state_matrix(x, labels)

        a,b,c,d = x[2],x[7],x[8],x[13]
        x[2],x[7],x[8],x[13] = _quarter_round_verbose(
            a,b,c,d,
            labels=[labels[2], labels[7], labels[8], labels[13]]
        )
        _print_state_matrix(x, labels)

        a,b,c,d = x[3],x[4],x[9],x[14]
        x[3],x[4],x[9],x[14] = _quarter_round_verbose(
            a,b,c,d,
            labels=[labels[3], labels[4], labels[9], labels[14]]
        )
        _print_state_matrix(x, labels)

    # Add initial state to x, serialize
    out_words = [(x[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    print("[ChaCha20] After 20 rounds, add initial state to produce block words:")
    for i, w in enumerate(out_words):
        print(f"   word[{i}] = (x[{i}] + state[{i}]) mod 2^32 = {w:#010x}")
    pause()
    out = b"".join(struct.pack("<I", w) for w in out_words)
    print("[ChaCha20] Produced 64-byte keystream block (LE words).")
    pause()
    return out

# -----------------------
# ChaCha20 encryption (calls block) — no overview here; call overviews externally
# -----------------------
def chacha20_encrypt_verbose(key32, nonce12, plaintext, initial_counter=1):
    out = bytearray()
    pos, counter = 0, initial_counter
    while pos < len(plaintext):
        block = chacha20_block_verbose(key32, counter, nonce12)
        chunk = plaintext[pos:pos+64]
        print(f"[ChaCha20] Encryption formula: C_block = P_block XOR keystream_block (counter={counter})")
        pause()
        for i, b in enumerate(chunk):
            out.append(b ^ block[i])
        pos += len(chunk)
        counter = (counter + 1) & 0xFFFFFFFF
    return bytes(out)

# -----------------------
# AEAD wrapper
# -----------------------
def _pad16(data): return b"" if len(data)%16==0 else b"\x00"*(16-(len(data)%16))

def aead_chacha20_poly1305_encrypt_verbose(key32, nonce12, aad, plaintext):
    # Print algorithm overviews first (so students see formulas before we're stepping through)
    poly1305_overview()
    chacha20_overview()

    # One-time poly key = ChaCha20(key, counter=0, nonce)[:32]
    print("[AEAD] Step: derive one-time Poly1305 key from ChaCha20 block0 (counter=0)")
    block0 = chacha20_block_verbose(key32, 0, nonce12)
    poly_key = block0[:32]
    print(f"[AEAD] poly_key (r||s) (first 32 bytes of block0) = {poly_key.hex()}")
    pause()

    # Encrypt starting at counter = 1
    ciphertext = chacha20_encrypt_verbose(key32, nonce12, plaintext, initial_counter=1)

    # Build MAC input: aad || pad16(aad) || ciphertext || pad16(ciphertext) || le64(len(aad)) || le64(len(ciphertext))
    mac_data = aad + _pad16(aad) + ciphertext + _pad16(ciphertext)
    mac_data += len(aad).to_bytes(8, "little")
    mac_data += len(ciphertext).to_bytes(8, "little")
    print("[AEAD] Tag input composition:")
    print("    TagInput = aad || pad16(aad) || ciphertext || pad16(ciphertext) || le64(len(aad)) || le64(len(ciphertext))")
    pause()

    # Compute Poly1305 tag (verbose)
    tag = poly1305_mac_verbose(mac_data, poly_key)
    print("[AEAD] Computed Poly1305 tag (16 bytes):", tag.hex())
    pause()
    return ciphertext, tag

def aead_chacha20_poly1305_decrypt_verbose(key32, nonce12, aad, ciphertext, tag):
    # Re-derive poly_key (block0)
    block0 = chacha20_block_verbose(key32, 0, nonce12)
    poly_key = block0[:32]
    mac_data = aad + _pad16(aad) + ciphertext + _pad16(ciphertext)
    mac_data += len(aad).to_bytes(8, "little")
    mac_data += len(ciphertext).to_bytes(8, "little")
    print("[AEAD] Verifying tag:")
    ok = poly1305_verify_verbose(tag, mac_data, poly_key)
    if not ok:
        raise ValueError("AEAD tag verification failed")
    plaintext = chacha20_encrypt_verbose(key32, nonce12, ciphertext, initial_counter=1)
    print("[AEAD] Decryption done (plaintext recovered).")
    return plaintext

# -----------------------
# CLI / main
# -----------------------
def main():
    global STEP_BY_STEP
    parser = argparse.ArgumentParser(description="Teaching ChaCha20-Poly1305 (verbose, step-through)")
    parser.add_argument("--auto", action="store_true", help="Run without pauses (no step-by-step)")
    args = parser.parse_args()
    STEP_BY_STEP = not args.auto

    # Example keys & data (small demo)
    key = bytes(range(32))
    nonce = bytes(range(12))
    aad = b"header"
    pt = b"Poly1305 + ChaCha20 AEAD teaching demo."

    print("=== ChaCha20-Poly1305 teaching demo ===")
    if STEP_BY_STEP:
        print("Running in step-by-step mode (pauses after each formula). Use --auto to disable.")
    else:
        print("Running in automatic mode (no pauses).")

    ct, tag = aead_chacha20_poly1305_encrypt_verbose(key, nonce, aad, pt)
    print("\n[Result] Ciphertext (hex):", ct.hex())
    print("[Result] Tag (hex):", tag.hex())

    # Demonstrate decrypt (verbose)
    try:
        recovered = aead_chacha20_poly1305_decrypt_verbose(key, nonce, aad, ct, tag)
        print("\n[Result] Recovered plaintext:", recovered)
    except Exception as e:
        print("Decryption / verification failed:", e)

if __name__ == "__main__":
    main()
