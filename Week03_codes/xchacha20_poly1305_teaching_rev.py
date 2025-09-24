#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Teaching Version — XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha) — Step-by-Step
# ----------------------------------------------------------------------------
# Verbosity levels:
#   0 = quiet (only outputs ct/tag or plaintext)
#   1 = high-level steps (state snapshots, lengths, r/s, MAC segments)
#   2 = per double-round state (after column+diagonal), Poly1305 per-block math
#   3 = per QUARTER-ROUND arithmetic (add/xor/rotl), full Poly1305 big-int steps
# Other lecture flags:
#   --demo-all-blocks    : print ChaCha block steps for all blocks (default: block0 + first data block)
#   --pause              : interactive pauses between phases
#   --show-mac-input     : hex dump of MAC input
#   --no-overview        : skip the algorithm overview banner
#
# Teaching code; NOT constant-time. Use vetted libraries in production.
import argparse
import hmac
import struct
from typing import Tuple

# ==============================
# Overview banner
# ==============================

def print_overview():
    print("""
================================================================================
XChaCha20-Poly1305 — Algorithm Overview (TEACHING MODE)
================================================================================

XChaCha20-Poly1305 (AEAD) extends ChaCha20-Poly1305 with a 192-bit nonce.
It derives a subkey using HChaCha20, then runs the standard IETF ChaCha20-Poly1305
under that subkey with a derived 96-bit nonce.

HChaCha20 (subkey derivation):
  • Input: 256-bit key K, 128-bit nonce N0 (first 16 bytes of the 24-byte nonce)
  • State (4×4 words, LE): constants, key, key, N0[0..3]  (no counter)
  • 20 rounds (10× {column, diagonal}); NO feedforward addition
  • Output subkey: concatenate state words [0..3] || [12..15] (LE) → 32 bytes

Derived nonce for ChaCha20:
  • N1 = 4 zero bytes (0x00000000) || last 8 bytes of the 24-byte nonce

AEAD (encrypt):
  1) Derive subkey SK = HChaCha20(K, N0); build N1 as above
  2) Derive Poly1305 one-time key from ChaCha20_block(SK, counter=0, N1):
       r || s = first 32 bytes of block0; clamp r with 0x0ffffffc0ffffffc0ffffffc0fffffff
  3) Encrypt PT using ChaCha20 stream under SK with counter=1 and nonce=N1:
       CT = PT XOR ChaCha20_stream(SK, 1, N1)
  4) MAC input: AAD || pad16(AAD) || CT || pad16(CT) || le64(|AAD|) || le64(|CT|)
     Tag = Poly1305(MAC input; r, s) over p = 2^130 - 5

AEAD (decrypt):
  1) SK = HChaCha20(K, N0); N1 = 0^32 || nonce[16:24]; derive (r,s) from block0
  2) Recompute tag' = Poly1305(AAD||pad||CT||pad||lenA||lenC; r,s)
  3) If tag' == tag → PT = CT XOR ChaCha20_stream(SK,1,N1); else reject

Notes & safety:
  • 24-byte nonces allow random selection with negligible collision risk.
  • Counter is 32-bit per (SK, N1): refuse messages that would exceed 2^32 blocks (~256 GiB).
  • This code is NOT constant-time and is for teaching only.
================================================================================
""")

# ==============================
# Utilities
# ==============================

def to_u32(x: int) -> int:
    return x & 0xffffffff

def rotl32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

def le_bytes_to_words(b: bytes):
    if len(b) % 4 != 0:
        raise ValueError("byte length must be multiple of 4")
    return list(struct.unpack("<" + "I" * (len(b)//4), b))

def words_to_le_bytes(*words: int) -> bytes:
    return struct.pack("<" + "I" * len(words), *[(w & 0xffffffff) for w in words])

def pad16(x: bytes) -> bytes:
    if len(x) % 16 == 0:
        return b""
    return b"\x00" * (16 - (len(x) % 16))

def le64(n: int) -> bytes:
    return struct.pack("<Q", n & ((1<<64)-1))

def hexstr(b: bytes) -> str:
    return b.hex()

def print_state(words, label="", vrb=1):
    if vrb <= 0:
        return
    print(f"[{label}] 4x4 state (little-endian 32-bit words):")
    for r in range(4):
        row = words[4*r:4*r+4]
        print("  " + " ".join(f"{w:08x}" for w in row))

def maybe_pause(do_pause: bool, msg="(press Enter)"):
    if do_pause:
        try:
            input(msg)
        except EOFError:
            pass

# ==============================
# ChaCha20 core (RFC 8439)
# ==============================

SIGMA = b"expand 32-byte k"  # 16 bytes

def quarterround_dbg(a: int, b: int, c: int, d: int, name: str, vrb: int):
    if vrb >= 3:
        print(f"  <{name}> a,b,c,d  = {a:08x} {b:08x} {c:08x} {d:08x}")
        print(f"   a += b  -> {((a+b)&0xffffffff):08x}")
    a = (a + b) & 0xffffffff; d ^= a; d = rotl32(d, 16)
    if vrb >= 3:
        print(f"   d ^= a  -> {d:08x}  (rotl16 applied)")
        print(f"   c += d  -> {((c+d)&0xffffffff):08x}")
    c = (c + d) & 0xffffffff; b ^= c; b = rotl32(b, 12)
    if vrb >= 3:
        print(f"   b ^= c  -> {b:08x}  (rotl12 applied)")
        print(f"   a += b  -> {((a+b)&0xffffffff):08x}")
    a = (a + b) & 0xffffffff; d ^= a; d = rotl32(d, 8)
    if vrb >= 3:
        print(f"   d ^= a  -> {d:08x}  (rotl8 applied)")
        print(f"   c += d  -> {((c+d)&0xffffffff):08x}")
    c = (c + d) & 0xffffffff; b ^= c; b = rotl32(b, 7)
    if vrb >= 3:
        print(f"   b ^= c  -> {b:08x}  (rotl7 applied)")
        print(f"  </{name}> a,b,c,d' = {a:08x} {b:08x} {c:08x} {d:08x}")
    return a, b, c, d

def quarterround(a: int, b: int, c: int, d: int):
    a = (a + b) & 0xffffffff; d ^= a; d = rotl32(d, 16)
    c = (c + d) & 0xffffffff; b ^= c; b = rotl32(b, 12)
    a = (a + b) & 0xffffffff; d ^= a; d = rotl32(d, 8)
    c = (c + d) & 0xffffffff; b ^= c; b = rotl32(b, 7)
    return a, b, c, d

def _rounds_20(working, vrb: int):
    for i in range(10):
        if vrb >= 2:
            print(f"[Round {i+1}/10] Column rounds")
        if vrb >= 3:
            working[0], working[4], working[8],  working[12] = quarterround_dbg(working[0], working[4], working[8],  working[12], "QR(0,4,8,12)", vrb)
            working[1], working[5], working[9],  working[13] = quarterround_dbg(working[1], working[5], working[9],  working[13], "QR(1,5,9,13)", vrb)
            working[2], working[6], working[10], working[14] = quarterround_dbg(working[2], working[6], working[10], working[14], "QR(2,6,10,14)", vrb)
            working[3], working[7], working[11], working[15] = quarterround_dbg(working[3], working[7], working[11], working[15], "QR(3,7,11,15)", vrb)
        else:
            working[0], working[4], working[8],  working[12] = quarterround(working[0], working[4], working[8],  working[12])
            working[1], working[5], working[9],  working[13] = quarterround(working[1], working[5], working[9],  working[13])
            working[2], working[6], working[10], working[14] = quarterround(working[2], working[6], working[10], working[14])
            working[3], working[7], working[11], working[15] = quarterround(working[3], working[7], working[11], working[15])
        if vrb >= 2:
            print_state(working, f" after column (round {i+1})", vrb)

        if vrb >= 2:
            print(f"[Round {i+1}/10] Diagonal rounds")
        if vrb >= 3:
            working[0], working[5], working[10], working[15] = quarterround_dbg(working[0], working[5], working[10], working[15], "QR(0,5,10,15)", vrb)
            working[1], working[6], working[11], working[12] = quarterround_dbg(working[1], working[6], working[11], working[12], "QR(1,6,11,12)", vrb)
            working[2], working[7], working[8],  working[13] = quarterround_dbg(working[2], working[7], working[8],  working[13], "QR(2,7,8,13)", vrb)
            working[3], working[4], working[9],  working[14] = quarterround_dbg(working[3], working[4], working[9],  working[14], "QR(3,4,9,14)", vrb)
        else:
            working[0], working[5], working[10], working[15] = quarterround(working[0], working[5], working[10], working[15])
            working[1], working[6], working[11], working[12] = quarterround(working[1], working[6], working[11], working[12])
            working[2], working[7], working[8],  working[13] = quarterround(working[2], working[7], working[8],  working[13])
            working[3], working[4], working[9],  working[14] = quarterround(working[3], working[4], working[9],  working[14])
        if vrb >= 2:
            print_state(working, f" after diagonal (round {i+1})", vrb)

def chacha20_block_verbose(key: bytes, counter: int, nonce: bytes, vrb: int, pause: bool) -> bytes:
    if len(key) != 32: raise ValueError("key must be 32 bytes")
    if len(nonce) != 12: raise ValueError("nonce must be 12 bytes (IETF)")
    k = le_bytes_to_words(key)
    n = le_bytes_to_words(nonce)
    const = le_bytes_to_words(SIGMA)
    state = [
        const[0], const[1], const[2], const[3],
        k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7],
        counter & 0xffffffff,
        n[0], n[1], n[2]
    ]
    print_state(state, f"ChaCha20 initial (counter={counter})", vrb)
    working = state.copy()
    _rounds_20(working, vrb)
    out_words = [(working[i] + state[i]) & 0xffffffff for i in range(16)]
    if vrb >= 1:
        print_state(out_words, "ChaCha20 final (before serialize)", vrb)
    maybe_pause(pause, "End of ChaCha20 block. Press Enter to continue...")
    return words_to_le_bytes(*out_words)

def chacha20_block(key: bytes, counter: int, nonce: bytes, verbose: int = 0, pause: bool = False) -> bytes:
    if verbose >= 1:
        return chacha20_block_verbose(key, counter, nonce, verbose, pause)
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("key=32B, nonce=12B required")
    k = le_bytes_to_words(key)
    n = le_bytes_to_words(nonce)
    const = le_bytes_to_words(SIGMA)
    state = [
        const[0], const[1], const[2], const[3],
        k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7],
        counter & 0xffffffff,
        n[0], n[1], n[2]
    ]
    w = state.copy()
    for _ in range(10):
        w[0], w[4], w[8],  w[12] = quarterround(w[0], w[4], w[8],  w[12])
        w[1], w[5], w[9],  w[13] = quarterround(w[1], w[5], w[9],  w[13])
        w[2], w[6], w[10], w[14] = quarterround(w[2], w[6], w[10], w[14])
        w[3], w[7], w[11], w[15] = quarterround(w[3], w[7], w[11], w[15])
        w[0], w[5], w[10], w[15] = quarterround(w[0], w[5], w[10], w[15])
        w[1], w[6], w[11], w[12] = quarterround(w[1], w[6], w[11], w[12])
        w[2], w[7], w[8],  w[13] = quarterround(w[2], w[7], w[8],  w[13])
        w[3], w[4], w[9],  w[14] = quarterround(w[3], w[4], w[9],  w[14])
    out_words = [(w[i] + state[i]) & 0xffffffff for i in range(16)]
    return words_to_le_bytes(*out_words)

# ----- HChaCha20 (no feedforward; output words 0..3 || 12..15) -----
def hchacha20_verbose(key: bytes, nonce16: bytes, vrb: int, pause: bool) -> bytes:
    if len(key) != 32: raise ValueError("key must be 32 bytes")
    if len(nonce16) != 16: raise ValueError("HChaCha20 needs 16-byte nonce (first 16 bytes of 24-byte XChaCha nonce)")
    k = le_bytes_to_words(key)
    n = le_bytes_to_words(nonce16)
    const = le_bytes_to_words(SIGMA)
    state = [
        const[0], const[1], const[2], const[3],
        k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7],
        n[0], n[1], n[2], n[3]
    ]
    print_state(state, "HChaCha20 initial (no counter; 128-bit nonce)", vrb)
    working = state.copy()
    _rounds_20(working, vrb)
    out = [working[0], working[1], working[2], working[3], working[12], working[13], working[14], working[15]]
    if vrb >= 1:
        print_state(working, "HChaCha20 final state (post 20 rounds)", vrb)
        print("HChaCha20 subkey (words): " + " ".join(f"{w:08x}" for w in out))
    maybe_pause(pause, "End of HChaCha20. Press Enter to continue...")
    return words_to_le_bytes(*out)

def hchacha20(key: bytes, nonce16: bytes, verbose: int = 0, pause: bool = False) -> bytes:
    if verbose >= 1:
        return hchacha20_verbose(key, nonce16, verbose, pause)
    k = le_bytes_to_words(key)
    n = le_bytes_to_words(nonce16)
    const = le_bytes_to_words(SIGMA)
    state = [
        const[0], const[1], const[2], const[3],
        k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7],
        n[0], n[1], n[2], n[3]
    ]
    w = state.copy()
    for _ in range(10):
        w[0], w[4], w[8],  w[12] = quarterround(w[0], w[4], w[8],  w[12])
        w[1], w[5], w[9],  w[13] = quarterround(w[1], w[5], w[9],  w[13])
        w[2], w[6], w[10], w[14] = quarterround(w[2], w[6], w[10], w[14])
        w[3], w[7], w[11], w[15] = quarterround(w[3], w[7], w[11], w[15])
        w[0], w[5], w[10], w[15] = quarterround(w[0], w[5], w[10], w[15])
        w[1], w[6], w[11], w[12] = quarterround(w[1], w[6], w[11], w[12])
        w[2], w[7], w[8],  w[13] = quarterround(w[2], w[7], w[8],  w[13])
        w[3], w[4], w[9],  w[14] = quarterround(w[3], w[4], w[9],  w[14])
    out_words = [w[0], w[1], w[2], w[3], w[12], w[13], w[14], w[15]]
    return words_to_le_bytes(*out_words)

# ==============================
# Poly1305
# ==============================

def clamp_r(r: int) -> int:
    return r & 0x0ffffffc0ffffffc0ffffffc0fffffff

def poly1305_key_gen(subkey: bytes, derived_nonce: bytes, verbose: int = 0, pause: bool = False) -> Tuple[bytes, bytes]:
    if verbose >= 1:
        print("[Poly1305 key-gen] Using ChaCha20 block (counter=0) under subkey to derive r||s")
    block0 = chacha20_block(subkey, 0, derived_nonce, verbose=verbose, pause=pause)
    r = block0[:16]
    s = block0[16:32]
    if verbose >= 1:
        print(f"  block0[0:16] = r = {r.hex()} (before clamp)")
        print(f"  block0[16:32]= s = {s.hex()}")
    return r, s

def poly1305_mac(msg: bytes, r_s: Tuple[bytes, bytes], show_mac_input: bool = False, verbose: int = 0, pause: bool = False) -> bytes:
    r_bytes, s_bytes = r_s
    if len(r_bytes) != 16 or len(s_bytes) != 16:
        raise ValueError("Poly1305 key must be 32 bytes split as 16+16 (r||s)")
    r_raw = int.from_bytes(r_bytes, "little")
    s = int.from_bytes(s_bytes, "little")
    r = clamp_r(r_raw)
    p = (1 << 130) - 5

    if verbose >= 1:
        print(f"[Poly1305] r_raw = {r_raw:032x}")
        print(f"[Poly1305] r_clamped = {r:032x}")
        print(f"[Poly1305] s = {s:032x}")
        maybe_pause(pause, "Clamped r. Press Enter to continue...")

    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i+16]
        n = int.from_bytes(block + b"\x01", "little")
        if verbose >= 2:
            print(f"[Poly1305] Block @{i:04d}: {block.hex():<34}  +01 -> n={n:x}")
            print(f"  acc = (acc + n) mod p")
        acc = (acc + n) % p
        if verbose >= 2:
            print(f"   => acc = {acc:x}")
            print("  acc = (acc * r) mod p")
        acc = (acc * r) % p
        if verbose >= 2:
            print(f"   => acc = {acc:x}")
    tag = (acc + s) % (1 << 128)
    if verbose >= 1:
        print(f"[Poly1305] Final: (acc + s) mod 2^128 = {tag:032x}")
        maybe_pause(pause, "End Poly1305. Press Enter to continue...")
    return tag.to_bytes(16, "little")

# ==============================
# XChaCha20 helpers
# ==============================

def xchacha20_derive(key: bytes, nonce24: bytes, verbose: int = 0, pause: bool = False):
    if len(nonce24) != 24:
        raise ValueError("XChaCha20 requires a 24-byte nonce")
    if verbose >= 1:
        print("[XChaCha20] Deriving subkey with HChaCha20 from first 16 bytes of nonce")
    subkey = hchacha20(key, nonce24[:16], verbose=verbose, pause=pause)
    derived_nonce = b"\x00\x00\x00\x00" + nonce24[16:]  # 4 NUL + last 8 bytes
    if verbose >= 1:
        print(f"[XChaCha20] Derived ChaCha20 nonce (96-bit) = 00000000 || {nonce24[16:].hex()} -> {derived_nonce.hex()}")
        maybe_pause(pause, "Proceed with AEAD under subkey and derived nonce. Press Enter...")
    return subkey, derived_nonce

def chacha20_keystream(key: bytes, initial_counter: int, nonce: bytes, length: int,
                       verbose: int = 0, pause: bool = False, demo_all_blocks: bool = False) -> bytes:
    blocks = []
    counter = initial_counter
    max_blocks = (1 << 32) - initial_counter
    needed_blocks = (length + 63) // 64
    if needed_blocks > max_blocks:
        raise ValueError("Message too long: 32-bit block counter would wrap.")
    for bi in range(needed_blocks):
        vrb = verbose if (demo_all_blocks or bi == 0) else 0
        blocks.append(chacha20_block(key, counter, nonce, verbose=vrb, pause=pause))
        counter = (counter + 1) & 0xffffffff
    return b"".join(blocks)[:length]

def chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes,
                 verbose: int = 0, pause: bool = False, demo_all_blocks: bool = False) -> bytes:
    ks = chacha20_keystream(key, counter, nonce, len(data), verbose=verbose, pause=pause, demo_all_blocks=demo_all_blocks)
    return bytes([a ^ b for a, b in zip(ks, data)])

# ==============================
# AEAD: XChaCha20-Poly1305
# ==============================

def aead_encrypt(key: bytes, nonce24: bytes, aad: bytes, plaintext: bytes,
                 verbose: int = 0, show_mac_input: bool = False, pause: bool = False, demo_all_blocks: bool = False):
    if len(key) != 32: raise ValueError("key must be 32 bytes")
    if len(nonce24) != 24: raise ValueError("nonce must be 24 bytes (XChaCha20)")
    if len(aad) >= (1<<64) or len(plaintext) >= (1<<64):
        raise ValueError("AAD or plaintext too long for RFC8439 length encoding.")

    subkey, n1 = xchacha20_derive(key, nonce24, verbose=verbose, pause=pause)
    r, s = poly1305_key_gen(subkey, n1, verbose=verbose, pause=pause)

    if verbose >= 1:
        print("[Encrypt] ChaCha20 stream XOR (counter starts at 1) under subkey")
    ciphertext = chacha20_xor(subkey, 1, n1, plaintext, verbose=verbose, pause=pause, demo_all_blocks=demo_all_blocks)

    mac_data = aad + pad16(aad) + ciphertext + pad16(ciphertext) + le64(len(aad)) + le64(len(ciphertext))
    if verbose >= 1:
        print("[MAC Input] AAD || pad16(AAD) || CT || pad16(CT) || le64(len(AAD)) || le64(len(CT))")
        print(f"  len(AAD)={len(aad)}  len(CT)={len(ciphertext)}")
        if show_mac_input:
            for off in range(0, len(mac_data), 16):
                chunk = mac_data[off:off+16]
                print(f"  {off:04x}: {chunk.hex()}")
        maybe_pause(pause, "Proceed to Poly1305 MAC. Press Enter...")

    tag = poly1305_mac(mac_data, (r, s), show_mac_input=show_mac_input, verbose=verbose, pause=pause)
    return ciphertext, tag

def aead_decrypt(key: bytes, nonce24: bytes, aad: bytes, ciphertext: bytes, tag: bytes,
                 verbose: int = 0, show_mac_input: bool = False, pause: bool = False, demo_all_blocks: bool = False):
    if len(tag) != 16:
        raise ValueError("tag must be 16 bytes")
    if len(nonce24) != 24:
        raise ValueError("nonce must be 24 bytes (XChaCha20)")
    if len(aad) >= (1<<64) or len(ciphertext) >= (1<<64):
        raise ValueError("AAD or ciphertext too long for RFC8439 length encoding.")

    subkey, n1 = xchacha20_derive(key, nonce24, verbose=verbose, pause=pause)
    r, s = poly1305_key_gen(subkey, n1, verbose=verbose, pause=pause)

    mac_data = aad + pad16(aad) + ciphertext + pad16(ciphertext) + le64(len(aad)) + le64(len(ciphertext))
    if verbose >= 1:
        print("[Recompute MAC]")
        print(f"  len(AAD)={len(aad)}  len(CT)={len(ciphertext)}")
        if show_mac_input:
            for off in range(0, len(mac_data), 16):
                chunk = mac_data[off:off+16]
                print(f"  {off:04x}: {chunk.hex()}")

    expect_tag = poly1305_mac(mac_data, (r, s), show_mac_input=show_mac_input, verbose=verbose, pause=pause)
    if not hmac.compare_digest(expect_tag, tag):
        if verbose >= 1:
            print(f"[Auth FAIL] expected: {expect_tag.hex()}  provided: {tag.hex()}")
        return None
    if verbose >= 1:
        print("[Auth OK] Decrypting...")
    plaintext = chacha20_xor(subkey, 1, n1, ciphertext, verbose=verbose, pause=pause, demo_all_blocks=demo_all_blocks)
    return plaintext

# ==============================
# Self-test (IETF draft A.3.1 dev-friendly vector)
# ==============================

def selftest(verbose: int = 2, pause: bool = False):
    key = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    nonce24 = bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    pt = bytes.fromhex(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
        "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
        "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
        "637265656e20776f756c642062652069742e"
    )
    if verbose >= 1:
        print("[Selftest] XChaCha20-Poly1305 A.3.1 vector")
    ct, tg = aead_encrypt(key, nonce24, aad, pt, verbose=verbose, show_mac_input=True, pause=pause)
    print("ciphertext:", ct.hex())
    print("tag       :", tg.hex())

# ==============================
# CLI
# ==============================

def parse_hex_or_utf8(s: str, is_hex: bool) -> bytes:
    if is_hex:
        s = s.strip().replace(" ", "").replace("\n", "")
        return bytes.fromhex(s)
    return s.encode("utf-8")

def main():
    ap = argparse.ArgumentParser(description="Lecture-Verbose XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_common(p):
        p.add_argument("--key", required=True, help="32-byte key (hex or utf8)")
        p.add_argument("--nonce", required=True, help="24-byte XChaCha nonce (hex or utf8)")
        p.add_argument("--aad", default="", help="Associated data (hex or utf8)")
        p.add_argument("--hex", action="store_true", help="Interpret inputs as hex")
        p.add_argument("--verbose", type=int, default=0, help="0..3 (3 = per quarter-round)")
        p.add_argument("--show-mac-input", action="store_true", help="Hex-dump MAC input segments")
        p.add_argument("--pause", action="store_true", help="Pause between phases (press Enter)")
        p.add_argument("--demo-all-blocks", action="store_true", help="Print steps for all ChaCha blocks (default: only block0 & first data block)")
        p.add_argument("--no-overview", action="store_true", help="Do not print the algorithm overview at start")

    pe = sub.add_parser("encrypt", help="Encrypt and authenticate")
    add_common(pe)
    pe.add_argument("--pt", required=True, help="Plaintext (hex or utf8)")

    pd = sub.add_parser("decrypt", help="Verify and decrypt")
    add_common(pd)
    pd.add_argument("--ct", required=True, help="Ciphertext (hex or utf8)")
    pd.add_argument("--tag", required=True, help="Tag (hex or utf8)")

    ps = sub.add_parser("selftest", help="XChaCha20-Poly1305 dev-friendly vector (verbose demo)")
    ps.add_argument("--verbose", type=int, default=2)
    ps.add_argument("--pause", action="store_true")
    ps.add_argument("--no-overview", action="store_true")

    args = ap.parse_args()

    if args.cmd == "encrypt":
        if not getattr(args, "no_overview", False):
            print_overview()
        key = parse_hex_or_utf8(args.key, args.hex)
        nonce = parse_hex_or_utf8(args.nonce, args.hex)
        aad = parse_hex_or_utf8(args.aad, args.hex) if args.aad else b""
        pt = parse_hex_or_utf8(args.pt, args.hex)
        ct, tag = aead_encrypt(key, nonce, aad, pt,
                               verbose=args.verbose,
                               show_mac_input=args.show_mac_input,
                               pause=args.pause,
                               demo_all_blocks=args.demo_all_blocks)
        print("ciphertext:", hexstr(ct))
        print("tag       :", hexstr(tag))

    elif args.cmd == "decrypt":
        if not getattr(args, "no_overview", False):
            print_overview()
        key = parse_hex_or_utf8(args.key, args.hex)
        nonce = parse_hex_or_utf8(args.nonce, args.hex)
        aad = parse_hex_or_utf8(args.aad, args.hex) if args.aad else b""
        ct = parse_hex_or_utf8(args.ct, args.hex)
        tg = parse_hex_or_utf8(args.tag, args.hex)
        pt = aead_decrypt(key, nonce, aad, ct, tg,
                          verbose=args.verbose,
                          show_mac_input=args.show_mac_input,
                          pause=args.pause,
                          demo_all_blocks=args.demo_all_blocks)
        if pt is None:
            print("Auth failed.")
        else:
            print("plaintext :", hexstr(pt))

    elif args.cmd == "selftest":
        if not getattr(args, "no_overview", False):
            print_overview()
        selftest(verbose=args.verbose, pause=args.pause)

if __name__ == "__main__":
    main()
