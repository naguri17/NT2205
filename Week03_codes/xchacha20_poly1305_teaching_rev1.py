#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Teaching Version — ChaCha20-Poly1305 & XChaCha20-Poly1305 (dual-mode) — Step-by-Step
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
#   --mode ietf|xchacha  : select 96-bit (IETF) or 192-bit (XChaCha) nonce mode
#
# Teaching code; NOT constant-time. Use vetted libraries in production.
import argparse
import hmac
import struct
from typing import Tuple

# ==============================
# Overview banner
# ==============================

def print_overview(mode: str):
    if mode == "ietf":
        print("""
================================================================================
ChaCha20-Poly1305 (RFC 8439) — Algorithm Overview (TEACHING MODE)
================================================================================

STATE (4×4 LE 32-bit words):
  [ c0  c1  c2  c3 ]   = "expand 32-byte k" (SIGMA)
  [ k0  k1  k2  k3 ]   = 256-bit key (first 4 words)
  [ k4  k5  k6  k7 ]   = 256-bit key (last 4 words)
  [ ctr n0  n1  n2 ]   = 32-bit block counter, 96-bit nonce

QUARTER-ROUND (a,b,c,d):
  a = (a + b);  d ^= a;  d = ROTL32(d,16)
  c = (c + d);  b ^= c;  b = ROTL32(b,12)
  a = (a + b);  d ^= a;  d = ROTL32(d, 8)
  c = (c + d);  b ^= c;  b = ROTL32(b, 7)

BLOCK FUNCTION:
  • 10 double-rounds (column then diagonal) = 20 rounds total
  • Add original state; serialize 16 words → 64-byte keystream block

AEAD ENCRYPT(key, 96-bit nonce, AAD, PT):
  1) Poly1305 key from ChaCha block0 (counter=0): r||s; clamp r with 0x0ffffffc…ffff
  2) Encrypt PT with ChaCha20 stream starting at counter=1
  3) MAC input: AAD || pad16(AAD) || CT || pad16(CT) || le64(|AAD|) || le64(|CT|)
     Tag = Poly1305(input; r,s) over p = 2^130 - 5

AEAD DECRYPT mirrors the above; verify tag before decrypt.

Notes & safety:
  • Nonce must be unique per key (reuse is catastrophic for both confidentiality and integrity).
  • 32-bit counter → refuse if message would exceed 2^32 blocks (~256 GiB).
  • Code here is not constant-time; for teaching only.
================================================================================
""")
    else:
        print("""
================================================================================
XChaCha20-Poly1305 — Algorithm Overview (TEACHING MODE)
================================================================================

Extends ChaCha20-Poly1305 with a 24-byte (192-bit) nonce.

HChaCha20 (subkey derivation):
  • Input: 256-bit key K, 128-bit nonce N0 (first 16 bytes of the 24-byte nonce)
  • State (4×4 words, LE): SIGMA, K, K, N0[0..3]; 20 rounds; NO feedforward
  • Output subkey: words [0..3] || [12..15] (LE) → 32 bytes

Derived nonce for ChaCha20:
  • N1 = 0x00000000 || nonce[16..23]   (4 zero bytes + last 8 bytes)

AEAD ENCRYPT(key, 24-byte nonce, AAD, PT):
  1) SK = HChaCha20(K, nonce[0..15]); N1 as above
  2) r||s from ChaCha block0 under SK with nonce N1; clamp r
  3) Encrypt PT with ChaCha20 stream (counter=1) under SK, N1
  4) MAC exactly as in IETF mode

AEAD DECRYPT mirrors the above; verify tag before decrypt.

Notes & safety:
  • Random 24-byte nonces have negligible collision probability; still treat nonces as unique.
  • 32-bit counter limit applies per (SK, N1).
  • Teaching code; not constant-time.
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
# ChaCha20 core
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

def poly1305_key_gen(chacha_key: bytes, chacha_nonce: bytes, verbose: int = 0, pause: bool = False) -> Tuple[bytes, bytes]:
    if verbose >= 1:
        print("[Poly1305 key-gen] Using ChaCha20 block (counter=0) to derive r||s")
    block0 = chacha20_block(chacha_key, 0, chacha_nonce, verbose=verbose, pause=pause)
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
# Mode helpers
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
# AEAD (dual-mode)
# ==============================

def aead_encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes, mode: str = "ietf",
                 verbose: int = 0, show_mac_input: bool = False, pause: bool = False, demo_all_blocks: bool = False):
    if len(key) != 32: raise ValueError("key must be 32 bytes")
    if len(aad) >= (1<<64) or len(plaintext) >= (1<<64):
        raise ValueError("AAD or plaintext too long for RFC8439 length encoding.")

    if mode == "ietf":
        if len(nonce) != 12: raise ValueError("IETF mode requires a 12-byte nonce")
        ch_key, ch_nonce = key, nonce
    elif mode == "xchacha":
        if len(nonce) != 24: raise ValueError("XChaCha mode requires a 24-byte nonce")
        ch_key, ch_nonce = xchacha20_derive(key, nonce, verbose=verbose, pause=pause)
    else:
        raise ValueError("mode must be 'ietf' or 'xchacha'")

    r, s = poly1305_key_gen(ch_key, ch_nonce, verbose=verbose, pause=pause)

    if verbose >= 1:
        print("[Encrypt] ChaCha20 stream XOR (counter starts at 1)")
    ciphertext = chacha20_xor(ch_key, 1, ch_nonce, plaintext, verbose=verbose, pause=pause, demo_all_blocks=demo_all_blocks)

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

def aead_decrypt(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes, tag: bytes, mode: str = "ietf",
                 verbose: int = 0, show_mac_input: bool = False, pause: bool = False, demo_all_blocks: bool = False):
    if len(tag) != 16:
        raise ValueError("tag must be 16 bytes")
    if len(aad) >= (1<<64) or len(ciphertext) >= (1<<64):
        raise ValueError("AAD or ciphertext too long for RFC8439 length encoding.")

    if mode == "ietf":
        if len(nonce) != 12: raise ValueError("IETF mode requires a 12-byte nonce")
        ch_key, ch_nonce = key, nonce
    elif mode == "xchacha":
        if len(nonce) != 24: raise ValueError("XChaCha mode requires a 24-byte nonce")
        ch_key, ch_nonce = xchacha20_derive(key, nonce, verbose=verbose, pause=pause)
    else:
        raise ValueError("mode must be 'ietf' or 'xchacha'")

    mac_data = aad + pad16(aad) + ciphertext + pad16(ciphertext) + le64(len(aad)) + le64(len(ciphertext))
    if verbose >= 1:
        print("[Recompute MAC]")
        print(f"  len(AAD)={len(aad)}  len(CT)={len(ciphertext)}")
        if show_mac_input:
            for off in range(0, len(mac_data), 16):
                chunk = mac_data[off:off+16]
                print(f"  {off:04x}: {chunk.hex()}")

    r, s = poly1305_key_gen(ch_key, ch_nonce, verbose=verbose, pause=pause)
    expect_tag = poly1305_mac(mac_data, (r, s), show_mac_input=show_mac_input, verbose=verbose, pause=pause)
    if not hmac.compare_digest(expect_tag, tag):
        if verbose >= 1:
            print(f"[Auth FAIL] expected: {expect_tag.hex()}  provided: {tag.hex()}")
        return None
    if verbose >= 1:
        print("[Auth OK] Decrypting...")
    plaintext = chacha20_xor(ch_key, 1, ch_nonce, ciphertext, verbose=verbose, pause=pause, demo_all_blocks=demo_all_blocks)
    return plaintext

# ==============================
# Self-tests
# ==============================

def selftest(mode: str = "ietf", verbose: int = 2, pause: bool = False):
    if mode == "ietf":
        # RFC 8439 AEAD test vector
        key = bytes.fromhex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0")
        nonce = bytes.fromhex("000000000102030405060708")
        aad = bytes.fromhex("f33388860000000000004e91")
        pt = bytes.fromhex(
            "496e7465726e65742d4472616674732061726520647261667420646f63756d656e747320"
            "76616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e"
            "64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c"
            "65746564206279206f7468657220646f63756d656e74732e20506c656173652072656665"
            "7220746f2052616661656c2773202253656375726520486173682d6261736564204d6573"
            "736167652041757468656e7469636174696f6e222e"
        )
        if verbose >= 1:
            print("[Selftest] IETF ChaCha20-Poly1305 (RFC 8439) vector")
    else:
        # XChaCha dev-friendly vector (draft-irtf-cfrg-xchacha A.3.1)
        key = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        nonce = bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657")
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        pt = bytes.fromhex(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
            "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
            "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
            "637265656e20776f756c642062652069742e"
        )
        if verbose >= 1:
            print("[Selftest] XChaCha20-Poly1305 A.3.1 vector")

    ct, tg = aead_encrypt(key, nonce, aad, pt, mode=mode, verbose=verbose, show_mac_input=True, pause=pause)
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
    ap = argparse.ArgumentParser(description="Lecture-Verbose ChaCha20-Poly1305 & XChaCha20-Poly1305 (dual-mode)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_common(p):
        p.add_argument("--mode", choices=["ietf", "xchacha"], default="ietf", help="AEAD mode (nonce length: ietf=12 bytes, xchacha=24 bytes)")
        p.add_argument("--key", required=True, help="32-byte key (hex or utf8)")
        p.add_argument("--nonce", required=True, help="Nonce (12 bytes for ietf; 24 bytes for xchacha)")
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

    ps = sub.add_parser("selftest", help="Built-in vectors (RFC 8439 for ietf; draft A.3.1 for xchacha)")
    ps.add_argument("--mode", choices=["ietf", "xchacha"], default="ietf")
    ps.add_argument("--verbose", type=int, default=2)
    ps.add_argument("--pause", action="store_true")
    ps.add_argument("--no-overview", action="store_true")

    args = ap.parse_args()

    if args.cmd == "encrypt":
        if not getattr(args, "no_overview", False):
            print_overview(args.mode)
        key = parse_hex_or_utf8(args.key, args.hex)
        nonce = parse_hex_or_utf8(args.nonce, args.hex)
        aad = parse_hex_or_utf8(args.aad, args.hex) if args.aad else b""
        pt = parse_hex_or_utf8(args.pt, args.hex)
        ct, tag = aead_encrypt(key, nonce, aad, pt, mode=args.mode,
                               verbose=args.verbose,
                               show_mac_input=args.show_mac_input,
                               pause=args.pause,
                               demo_all_blocks=args.demo_all_blocks)
        print("ciphertext:", hexstr(ct))
        print("tag       :", hexstr(tag))

    elif args.cmd == "decrypt":
        if not getattr(args, "no_overview", False):
            print_overview(args.mode)
        key = parse_hex_or_utf8(args.key, args.hex)
        nonce = parse_hex_or_utf8(args.nonce, args.hex)
        aad = parse_hex_or_utf8(args.aad, args.hex) if args.aad else b""
        ct = parse_hex_or_utf8(args.ct, args.hex)
        tg = parse_hex_or_utf8(args.tag, args.hex)
        pt = aead_decrypt(key, nonce, aad, ct, tg, mode=args.mode,
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
            print_overview(args.mode)
        selftest(mode=args.mode, verbose=args.verbose, pause=args.pause)

if __name__ == "__main__":
    main()
