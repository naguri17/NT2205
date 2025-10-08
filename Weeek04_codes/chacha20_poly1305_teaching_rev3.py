#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Teaching Version of ChaCha20-Poly1305 (RFC 7539 / IETF AEAD) — Step-by-Step
# REV3: Extended input handling (utf-8, hex, binary files), optional key derivation, better validations & UX.
# ----------------------------------------------------------------------------
# What's new in REV3:
# - You can now feed key/nonce/AAD/tag from *either* a UTF‑8/hex string *or* a binary file.
#   Use --key-file/--nonce-file/--aad-file/--tag-file for raw bytes, or --key/--nonce/--aad/--tag for text.
#   For strings, pass --hex to parse as hex; otherwise they are UTF-8 encoded bytes.
# - Files are read as raw bytes; use "-" to read from STDIN (e.g., for PT/CT or keys piped in).
# - Optional --key-derive sha256 can stretch any string into a 32-byte key (for demos *only*).
# - Clear length checks and helpful error messages for key (32B) & nonce (12B).
# - Backwards compatible with the original CLI.
#
# SECURITY NOTE: This is a *teaching* implementation (not constant-time). For production, use a vetted crypto library.
import argparse
import hmac
import struct
import hashlib
import sys
from typing import Tuple, Optional
import pathlib

def print_overview():
    print("""
================================================================================
ChaCha20-Poly1305 (RFC 7539) — Algorithm Overview (TEACHING MODE)
================================================================================

STATE (ChaCha20 4×4 little-endian words):
  [ c0  c1  c2  c3 ]   = "expand 32-byte k" (SIGMA)
  [ k0  k1  k2  k3 ]   = 256-bit key (first 4 words)
  [ k4  k5  k6  k7 ]   = 256-bit key (last 4 words)
  [ ctr n0  n1  n2 ]   = 32-bit block counter, 96-bit nonce (IETF)

QUARTER-ROUND (on words a,b,c,d):
  a = (a + b);  d ^= a;  d = ROTL32(d, 16)
  c = (c + d);  b ^= c;  b = ROTL32(b, 12)
  a = (a + b);  d ^= a;  d = ROTL32(d,  8)
  c = (c + d);  b ^= c;  b = ROTL32(b,  7)

BLOCK FUNCTION:
  • Start from the state above
  • 10 double-rounds (column then diagonal rounds; total 20 rounds)
  • Add original state; serialize 16 words → 64-byte keystream block

AEAD ENCRYPT(key, nonce, AAD, PT):
  1) Derive one-time Poly1305 key from block0:
       r || s = ChaCha20_block(key, counter=0, nonce)
       Clamp r by mask 0x0ffffffc0ffffffc0ffffffc0fffffff
  2) Encrypt plaintext using ChaCha20 stream starting at counter=1:
       CT = PT XOR ChaCha20_stream(key, counter=1, nonce)
  3) Build MAC input:
       data = AAD || pad16(AAD) || CT || pad16(CT) || le64(len(AAD)) || le64(len(CT))
       (pad16(x) = 0 to next multiple of 16; lengths encoded as 64-bit little-endian)
       (Poly1305 processes 16B blocks with an implicit +0x01 byte each block)
  4) Compute tag:
       TAG = Poly1305(data; r, s)   over field p = 2^130 - 5
  Output: (CT, TAG)

AEAD DECRYPT(key, nonce, AAD, CT, TAG):
  1) r || s = ChaCha20_block(key, 0, nonce); clamp r
  2) Recompute tag' = Poly1305(AAD||pad||CT||pad||lenA||lenC; r,s)
  3) If tag' == TAG (constant-time compare) → decrypt:
       PT = CT XOR ChaCha20_stream(key, counter=1, nonce)
     Else → reject.

SECURITY/BOUNDS:
  • Nonce MUST be unique per (key, nonce) message; reuse is catastrophic.
  • Counter is 32-bit: refuse if encryption would exceed 2^32 blocks (~256 GiB).
  • len(AAD), len(PT) must fit in 64-bit (RFC 7539 footer encoding).
  • This teaching code is not constant-time; use vetted libraries in production.
================================================================================
""")

# ==============================
# Utilities
# ==============================

def read_bytes(path: str) -> bytes:
    """Read raw bytes. If path == '-', read from stdin.buffer."""
    if path == '-':
        return sys.stdin.buffer.read()
    return pathlib.Path(path).read_bytes()

def write_file_bytes(path: str, data: bytes):
    pathlib.Path(path).write_bytes(data)

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
    return b"\\x00" * (16 - (len(x) % 16))

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
# ChaCha20 core (RFC 7539)
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
    print_state(state, f"initial (counter={counter})", vrb)
    working = state.copy()

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

    out_words = [(working[i] + state[i]) & 0xffffffff for i in range(16)]
    if vrb >= 1:
        print_state(out_words, "final (before serialize)", vrb)
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

def chacha20_keystream(key: bytes, initial_counter: int, nonce: bytes, length: int,
                       verbose: int = 0, pause: bool = False, demo_all_blocks: bool = False) -> bytes:
    blocks = []
    counter = initial_counter
    max_blocks = (1 << 32) - initial_counter
    needed_blocks = (length + 63) // 64
    if needed_blocks > max_blocks:
        raise ValueError("Message too long: 32-bit block counter would wrap.")
    for bi in range(N := needed_blocks):
        vrb = verbose if (demo_all_blocks or bi == 0) else 0
        blocks.append(chacha20_block(key, counter, nonce, verbose=vrb, pause=pause))
        counter = (counter + 1) & 0xffffffff
    return b"".join(blocks)[:length]

def chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes,
                 verbose: int = 0, pause: bool = False, demo_all_blocks: bool = False) -> bytes:
    ks = chacha20_keystream(key, counter, nonce, len(data), verbose=verbose, pause=pause, demo_all_blocks=demo_all_blocks)
    return bytes([a ^ b for a, b in zip(ks, data)])

# ==============================
# Poly1305 (RFC 7539)
# ==============================

def clamp_r(r: int) -> int:
    return r & 0x0ffffffc0ffffffc0ffffffc0fffffff

def poly1305_key_gen(key: bytes, nonce: bytes, verbose: int = 0, pause: bool = False) -> Tuple[bytes, bytes]:
    if verbose >= 1:
        print("[Poly1305 key-gen] Using ChaCha20 block with counter=0 to derive r||s")
    block0 = chacha20_block(key, 0, nonce, verbose=verbose, pause=pause)
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
        n = int.from_bytes(block + b"\\x01", "little")
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
# AEAD: ChaCha20-Poly1305 (RFC 7539)
# ==============================

def aead_encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes,
                 verbose: int = 0, show_mac_input: bool = False, pause: bool = False, demo_all_blocks: bool = False):
    if len(key) != 32: raise ValueError("key must be 32 bytes")
    if len(nonce) != 12: raise ValueError("nonce must be 12 bytes (IETF)")
    if len(aad) >= (1<<64) or len(plaintext) >= (1<<64):
        raise ValueError("AAD or plaintext too long for RFC7539 length encoding.")

    r, s = poly1305_key_gen(key, nonce, verbose=verbose, pause=pause)

    if verbose >= 1:
        print("[Encrypt] ChaCha20 stream XOR (counter starts at 1)")
    ciphertext = chacha20_xor(key, 1, nonce, plaintext, verbose=verbose, pause=pause, demo_all_blocks=demo_all_blocks)

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

def aead_decrypt(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes, tag: bytes,
                 verbose: int = 0, show_mac_input: bool = False, pause: bool = False, demo_all_blocks: bool = False):
    if len(tag) != 16:
        raise ValueError("tag must be 16 bytes")
    if len(aad) >= (1<<64) or len(ciphertext) >= (1<<64):
        raise ValueError("AAD or ciphertext too long for RFC7539 length encoding.")

    r, s = poly1305_key_gen(key, nonce, verbose=verbose, pause=pause)

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
    plaintext = chacha20_xor(key, 1, nonce, ciphertext, verbose=verbose, pause=pause, demo_all_blocks=demo_all_blocks)
    return plaintext

# ==============================
# Input parsing helpers (NEW)
# ==============================

def parse_hex_or_utf8(s: str, is_hex: bool) -> bytes:
    """Backward-compatible: interpret string as hex if --hex else UTF-8."""
    if is_hex:
        s = s.strip().replace(" ", "").replace("\\n", "")
        return bytes.fromhex(s)
    return s.encode("utf-8")  # may include Vietnamese, emojis, etc.

def choose_bytes(name: str, value: Optional[str], file: Optional[str], is_hex: bool, required: bool) -> Optional[bytes]:
    """Choose between a string value and a file (raw bytes). Prohibit both set simultaneously."""
    if value and file:
        raise ValueError(f"Provide either --{name} or --{name}-file, not both.")
    if file:
        return read_bytes(file)
    if value is not None:
        return parse_hex_or_utf8(value, is_hex)
    if required:
        raise ValueError(f"Missing required input: --{name} or --{name}-file")
    return None

def ensure_len(name: str, b: bytes, expected_len: int):
    if len(b) != expected_len:
        raise ValueError(f"{name} must be exactly {expected_len} bytes, got {len(b)}.")

# ==============================
# Self-test (RFC 7539)
# ==============================

def selftest(verbose: int = 2, pause: bool = False):
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
    ct, tg = aead_encrypt(key, nonce, aad, pt, verbose=verbose, show_mac_input=True, pause=pause)
    print("ciphertext:", ct.hex())
    print("tag       :", tg.hex())

# ==============================
# CLI
# ==============================

def main():
    ap = argparse.ArgumentParser(description="Lecture-Verbose ChaCha20-Poly1305 (RFC 7539) — REV3")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_common(p):
        # Inputs may come from *either* string or file. Strings: utf-8 by default, or hex if --hex.
        p.add_argument("--key", help="Key as utf-8 or hex (32B after processing)" )
        p.add_argument("--key-file", help="Read key bytes from file (or '-' for stdin)")
        p.add_argument("--nonce", help="Nonce as utf-8 or hex (12B after processing)" )
        p.add_argument("--nonce-file", help="Read nonce bytes from file (or '-' for stdin)")
        p.add_argument("--aad", help="AAD as utf-8 or hex (optional)")
        p.add_argument("--aad-file", help="Read AAD bytes from file (or '-' for stdin)")

        p.add_argument("--hex", action="store_true", help="Interpret *string* inputs as hex (files are raw bytes)")
        p.add_argument("--key-derive", choices=["none","sha256"], default="none",
                       help="Derive a 32-byte key from a *string* via SHA-256 (teaching convenience; do NOT use in prod)")

        p.add_argument("--verbose", type=int, default=0, help="0..3 (3 = per quarter-round)")
        p.add_argument("--show-mac-input", action="store_true", help="Hex-dump MAC input segments")
        p.add_argument("--pause", action="store_true", help="Pause between phases (press Enter)")
        p.add_argument("--demo-all-blocks", action="store_true",
                       help="Print steps for all ChaCha blocks (default: only block0 & first data block)")
        p.add_argument("--no-overview", action="store_true", help="Do not print the algorithm overview at start")

    # Encrypt parser
    pe = sub.add_parser("encrypt", help="Encrypt and authenticate")
    add_common(pe)
    pe.add_argument("--pt", help="Plaintext as utf-8 or hex (mutually exclusive with --pt-file)")
    pe.add_argument("--pt-file", help="Plaintext file (raw bytes) or '-' for stdin")
    pe.add_argument("--out-ct", default="ciphertext.bin", help="Output file for ciphertext")
    pe.add_argument("--out-tag", default="tag.bin", help="Output file for tag")

    # Decrypt parser
    pd = sub.add_parser("decrypt", help="Verify and decrypt")
    add_common(pd)
    pd.add_argument("--ct", help="Ciphertext as utf-8 or hex (mutually exclusive with --ct-file)")
    pd.add_argument("--ct-file", help="Ciphertext file (raw bytes) or '-' for stdin")
    pd.add_argument("--tag", help="Tag as utf-8 or hex (mutually exclusive with --tag-file)" )
    pd.add_argument("--tag-file", help="Tag file (raw 16B) or '-' for stdin")
    pd.add_argument("--out-pt", default="plaintext.bin", help="Output file for decrypted plaintext")

    # Selftest parser
    ps = sub.add_parser("selftest", help="RFC 7539 vector (verbose demo)")
    ps.add_argument("--verbose", type=int, default=2)
    ps.add_argument("--pause", action="store_true")
    ps.add_argument("--no-overview", action="store_true")

    args = ap.parse_args()

    # -----------------------------------------------------------
    if args.cmd == "encrypt":
        if not getattr(args, "no_overview", False):
            print_overview()

        key = choose_bytes("key", args.key, args.key_file, args.hex, required=True)
        nonce = choose_bytes("nonce", args.nonce, args.nonce_file, args.hex, required=True)
        aad = choose_bytes("aad", args.aad, args.aad_file, args.hex, required=False) or b""

        # Optional key derivation for *string* keys only (teaching convenience).
        if args.key_derive != "none" and args.key is not None and args.key_file is None:
            key = hashlib.sha256(key).digest()
            print("[Key-Derive] key := SHA-256(utf8-or-hex-input)")
        # Validate lengths
        ensure_len("key", key, 32)
        ensure_len("nonce", nonce, 12)

        # Plaintext selection
        if args.pt_file and args.pt:
            raise ValueError("Provide either --pt or --pt-file, not both.")
        if args.pt_file:
            pt = read_bytes(args.pt_file)
        elif args.pt is not None:
            pt = parse_hex_or_utf8(args.pt, args.hex)
        else:
            raise ValueError("Must provide either --pt or --pt-file (use '-' to read PT from stdin)")

        ct, tag = aead_encrypt(
            key, nonce, aad, pt,
            verbose=args.verbose,
            show_mac_input=args.show_mac_input,
            pause=args.pause,
            demo_all_blocks=args.demo_all_blocks
        )

        print("ciphertext:", hexstr(ct))
        print("tag       :", hexstr(tag))

        write_file_bytes(args.out_ct, ct)
        write_file_bytes(args.out_tag, tag)
        print(f"[Saved] Ciphertext → {args.out_ct}, Tag → {args.out_tag}")

    elif args.cmd == "decrypt":
        if not getattr(args, "no_overview", False):
            print_overview()

        key = choose_bytes("key", args.key, args.key_file, args.hex, required=True)
        nonce = choose_bytes("nonce", args.nonce, args.nonce_file, args.hex, required=True)
        aad = choose_bytes("aad", args.aad, args.aad_file, args.hex, required=False) or b""

        if args.key_derive != "none" and args.key is not None and args.key_file is None:
            key = hashlib.sha256(key).digest()
            print("[Key-Derive] key := SHA-256(utf8-or-hex-input)")
        ensure_len("key", key, 32)
        ensure_len("nonce", nonce, 12)

        # Ciphertext & Tag selection
        if args.ct_file and args.ct:
            raise ValueError("Provide either --ct or --ct-file, not both.")
        if args.tag_file and args.tag:
            raise ValueError("Provide either --tag or --tag-file, not both.")

        if args.ct_file:
            ct = read_bytes(args.ct_file)
        elif args.ct is not None:
            ct = parse_hex_or_utf8(args.ct, args.hex)
        else:
            raise ValueError("Must provide either --ct or --ct-file (use '-' to read CT from stdin)")

        if args.tag_file:
            tg = read_bytes(args.tag_file)
        elif args.tag is not None:
            tg = parse_hex_or_utf8(args.tag, args.hex)
        else:
            raise ValueError("Must provide either --tag or --tag-file (use '-' to read TAG from stdin)")

        pt = aead_decrypt(
            key, nonce, aad, ct, tg,
            verbose=args.verbose,
            show_mac_input=args.show_mac_input,
            pause=args.pause,
            demo_all_blocks=args.demo_all_blocks
        )

        if pt is None:
            print("Auth failed.")
        else:
            print("plaintext :", hexstr(pt))
            write_file_bytes(args.out_pt, pt)
            print(f"[Saved] Plaintext → {args.out_pt}")

    elif args.cmd == "selftest":
        if not getattr(args, "no_overview", False):
            print_overview()
        selftest(verbose=args.verbose, pause=args.pause)

if __name__ == "__main__":
    main()
